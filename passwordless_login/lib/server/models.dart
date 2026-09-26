import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';

/// The relying-party identifier both sides put in every signed payload.
///
/// It is a plain string chosen by this demo, **not** an origin the OS
/// verifies: a look-alike app could ask the user to sign a payload with the
/// same `rp`. That is why this demo is replay-resistant but not
/// phishing-resistant (unlike FIDO/WebAuthn, where the platform binds the
/// signature to the calling origin).
const String relyingPartyId = 'passwordless-login.example';

/// The mock server's endpoints.
abstract final class ApiRoutes {
  /// `{username, platform}` → attestation challenge.
  static const String registerBegin = '/register/begin';

  /// `{username, challengeId, publicKey, attestationChain, …}` → account,
  /// attestation report and a one-time recovery code.
  static const String registerFinish = '/register/finish';

  /// `{username}` → login nonce and the account's active device keys.
  static const String loginBegin = '/login/begin';

  /// `{userId, deviceKeyId, challengeId, signature}` → session.
  static const String loginFinish = '/login/finish';

  /// `{username, recoveryCode, platform}` → attestation challenge for a
  /// replacement key.
  static const String recoveryBegin = '/recovery/begin';

  /// Like [registerFinish], plus the recovery code; supersedes old keys.
  static const String recoveryFinish = '/recovery/finish';

  /// `{userId, deviceKeyId}` → the server's record of a device key.
  static const String deviceStatus = '/devices/status';

  /// `{userId, deviceKeyId}` → nonce for a signed unbind request.
  static const String unbindBegin = '/devices/unbind/begin';

  /// `{userId, deviceKeyId, challengeId, signature}` → key unbound.
  static const String unbindFinish = '/devices/unbind/finish';

  /// `{token}` → session revoked.
  static const String logout = '/logout';
}

/// Lower-cases and trims a username.
String normalizeUsername(String input) => input.trim().toLowerCase();

final RegExp _usernamePattern = RegExp(r'^[a-z0-9][a-z0-9._-]{2,31}$');

/// Why [username] (already normalized) is invalid, or `null` if it is fine.
String? usernameProblem(String username) {
  if (username.isEmpty) return 'Enter a username';
  if (!_usernamePattern.hasMatch(username)) {
    return '3–32 characters: letters, digits, dot, dash or underscore';
  }
  return null;
}

/// Challenge purposes. A challenge issued for one purpose is rejected for
/// any other, so a login signature can never be reused to unbind a device.
abstract final class Purposes {
  /// Attestation challenge for a new account.
  static const String register = 'register';

  /// Attestation challenge for a replacement key (recovery code).
  static const String recovery = 'recovery';

  /// Login nonce.
  static const String login = 'login';

  /// Nonce for the signed "unbind this device" request.
  static const String unbind = 'unbind';
}

/// The exact bytes a device signs to answer a nonce.
///
/// Canonical JSON (sorted keys, no whitespace) of
/// `{challengeId, nonce, purpose, rp, userId}`. The server rebuilds these
/// bytes from its **own** stored challenge; it never re-serializes JSON the
/// client sent back.
Uint8List signedChallengePayload({
  required String purpose,
  required String rp,
  required String userId,
  required String challengeId,
  required String nonceBase64,
}) =>
    canonicalJsonBytes(signedChallengeFields(
      purpose: purpose,
      rp: rp,
      userId: userId,
      challengeId: challengeId,
      nonceBase64: nonceBase64,
    ));

/// The fields of [signedChallengePayload], for display.
Map<String, Object?> signedChallengeFields({
  required String purpose,
  required String rp,
  required String userId,
  required String challengeId,
  required String nonceBase64,
}) =>
    {
      'purpose': purpose,
      'rp': rp,
      'userId': userId,
      'challengeId': challengeId,
      'nonce': nonceBase64,
    };

/// Lifecycle of a device key on the server.
enum DeviceKeyStatus {
  /// Accepted for login.
  active,

  /// Replaced by a key registered with the recovery code.
  superseded,

  /// Removed by a signed unbind request.
  unbound,
}

/// A user account on the mock server.
class UserRecord {
  /// Creates a record.
  const UserRecord({
    required this.userId,
    required this.username,
    required this.createdAt,
    required this.recoverySalt,
    required this.recoveryCodeHash,
    this.recoveryCodeIssuedAt,
  });

  /// Restores a record from [toJson].
  factory UserRecord.fromJson(Map<String, dynamic> json) => UserRecord(
        userId: json['userId'] as String,
        username: json['username'] as String,
        createdAt: DateTime.parse(json['createdAt'] as String),
        recoverySalt: json['recoverySalt'] as String,
        recoveryCodeHash: json['recoveryCodeHash'] as String,
        recoveryCodeIssuedAt: json['recoveryCodeIssuedAt'] == null
            ? null
            : DateTime.parse(json['recoveryCodeIssuedAt'] as String),
      );

  /// Opaque server id, e.g. `u_3f9a…`.
  final String userId;

  /// Lower-case username.
  final String username;

  /// Registration time.
  final DateTime createdAt;

  /// Random salt for [recoveryCodeHash], hex.
  final String recoverySalt;

  /// SHA-256 of salt and the one-time recovery code. The code itself is
  /// shown to the user once and never stored.
  final String recoveryCodeHash;

  /// When the current recovery code was issued.
  final DateTime? recoveryCodeIssuedAt;

  /// Copy with a new recovery code hash.
  UserRecord withRecoveryCode({
    required String salt,
    required String hash,
    required DateTime issuedAt,
  }) =>
      UserRecord(
        userId: userId,
        username: username,
        createdAt: createdAt,
        recoverySalt: salt,
        recoveryCodeHash: hash,
        recoveryCodeIssuedAt: issuedAt,
      );

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'userId': userId,
        'username': username,
        'createdAt': createdAt.toUtc().toIso8601String(),
        'recoverySalt': recoverySalt,
        'recoveryCodeHash': recoveryCodeHash,
        'recoveryCodeIssuedAt': recoveryCodeIssuedAt?.toUtc().toIso8601String(),
      };
}

/// A device key bound to a user.
class DeviceKeyRecord {
  /// Creates a record.
  const DeviceKeyRecord({
    required this.deviceKeyId,
    required this.userId,
    required this.alias,
    required this.publicKey,
    required this.algorithm,
    required this.platform,
    required this.trustTier,
    required this.attestation,
    required this.createdAt,
    required this.allowDeviceCredentials,
    required this.invalidateOnEnrollment,
    this.status = DeviceKeyStatus.active,
    this.statusChangedAt,
    this.supersededBy,
    this.lastLoginAt,
    this.lastAuthenticationType,
    this.loginCount = 0,
    this.registrationAuthenticationType,
  });

  /// Restores a record from [toJson].
  factory DeviceKeyRecord.fromJson(Map<String, dynamic> json) =>
      DeviceKeyRecord(
        deviceKeyId: json['deviceKeyId'] as String,
        userId: json['userId'] as String,
        alias: json['alias'] as String,
        publicKey: json['publicKey'] as String,
        algorithm:
            SignatureAlgorithm.values.byName(json['algorithm'] as String),
        platform: json['platform'] as String,
        trustTier: TrustTier.values.byName(json['trustTier'] as String),
        attestation: json['attestation'] as Map<String, dynamic>,
        createdAt: DateTime.parse(json['createdAt'] as String),
        allowDeviceCredentials: json['allowDeviceCredentials'] as bool,
        invalidateOnEnrollment: json['invalidateOnEnrollment'] as bool,
        status: DeviceKeyStatus.values.byName(json['status'] as String),
        statusChangedAt: json['statusChangedAt'] == null
            ? null
            : DateTime.parse(json['statusChangedAt'] as String),
        supersededBy: json['supersededBy'] as String?,
        lastLoginAt: json['lastLoginAt'] == null
            ? null
            : DateTime.parse(json['lastLoginAt'] as String),
        lastAuthenticationType: json['lastAuthenticationType'] as String?,
        loginCount: json['loginCount'] as int? ?? 0,
        registrationAuthenticationType:
            json['registrationAuthenticationType'] as String?,
      );

  /// Opaque server id, e.g. `dk_3f9a…`.
  final String deviceKeyId;

  /// Owner.
  final String userId;

  /// The key alias on the device (`acct_…`). Informational: the server
  /// identifies keys by [deviceKeyId] and [publicKey].
  final String alias;

  /// SPKI DER, base64 (the plugin's `publicKey`).
  final String publicKey;

  /// Signature algorithm derived from the key type at registration
  /// (ECDSA P-256 SHA-256, or RSA PKCS#1 v1.5 SHA-256 on Windows).
  final SignatureAlgorithm algorithm;

  /// The platform the client **declared**. Only the attestation (Android)
  /// proves anything about the device.
  final String platform;

  /// What the attestation proved.
  final TrustTier trustTier;

  /// The [AttestationReport] as JSON.
  final Map<String, dynamic> attestation;

  /// Registration time.
  final DateTime createdAt;

  /// Declared `useDeviceCredentials` (the attested `userAuthType` is the
  /// verifiable version on Android).
  final bool allowDeviceCredentials;

  /// Declared `setInvalidatedByBiometricEnrollment`.
  final bool invalidateOnEnrollment;

  /// Lifecycle status.
  final DeviceKeyStatus status;

  /// When [status] last changed.
  final DateTime? statusChangedAt;

  /// The replacement key, when [DeviceKeyStatus.superseded].
  final String? supersededBy;

  /// Last successful login.
  final DateTime? lastLoginAt;

  /// Client-reported `authenticationType` of the last login. Recorded for
  /// audit only: it is not signed, so trust is never based on it.
  final String? lastAuthenticationType;

  /// Successful logins.
  final int loginCount;

  /// Client-reported `authenticationType` of key creation.
  final String? registrationAuthenticationType;

  /// Whether login is accepted with this key.
  bool get isActive => status == DeviceKeyStatus.active;

  /// The stored attestation report.
  AttestationReport get report => AttestationReport.fromJson(attestation);

  /// SHA-256 fingerprint of the public key, hex.
  String get fingerprint => ParsedPublicKey.parse(publicKey).fingerprint;

  /// Copy with changes.
  DeviceKeyRecord copyWith({
    DeviceKeyStatus? status,
    DateTime? statusChangedAt,
    String? supersededBy,
    DateTime? lastLoginAt,
    String? lastAuthenticationType,
    int? loginCount,
  }) =>
      DeviceKeyRecord(
        deviceKeyId: deviceKeyId,
        userId: userId,
        alias: alias,
        publicKey: publicKey,
        algorithm: algorithm,
        platform: platform,
        trustTier: trustTier,
        attestation: attestation,
        createdAt: createdAt,
        allowDeviceCredentials: allowDeviceCredentials,
        invalidateOnEnrollment: invalidateOnEnrollment,
        status: status ?? this.status,
        statusChangedAt: statusChangedAt ?? this.statusChangedAt,
        supersededBy: supersededBy ?? this.supersededBy,
        lastLoginAt: lastLoginAt ?? this.lastLoginAt,
        lastAuthenticationType:
            lastAuthenticationType ?? this.lastAuthenticationType,
        loginCount: loginCount ?? this.loginCount,
        registrationAuthenticationType: registrationAuthenticationType,
      );

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'deviceKeyId': deviceKeyId,
        'userId': userId,
        'alias': alias,
        'publicKey': publicKey,
        'algorithm': algorithm.name,
        'platform': platform,
        'trustTier': trustTier.name,
        'attestation': attestation,
        'createdAt': createdAt.toUtc().toIso8601String(),
        'allowDeviceCredentials': allowDeviceCredentials,
        'invalidateOnEnrollment': invalidateOnEnrollment,
        'status': status.name,
        'statusChangedAt': statusChangedAt?.toUtc().toIso8601String(),
        'supersededBy': supersededBy,
        'lastLoginAt': lastLoginAt?.toUtc().toIso8601String(),
        'lastAuthenticationType': lastAuthenticationType,
        'loginCount': loginCount,
        'registrationAuthenticationType': registrationAuthenticationType,
      };
}

/// A session issued after a verified login. Kept in memory only.
class SessionRecord {
  /// Creates a session.
  const SessionRecord({
    required this.token,
    required this.userId,
    required this.username,
    required this.deviceKeyId,
    required this.trustTier,
    required this.issuedAt,
    required this.expiresAt,
  });

  /// Restores a session from [toJson].
  factory SessionRecord.fromJson(Map<String, dynamic> json) => SessionRecord(
        token: json['token'] as String,
        userId: json['userId'] as String,
        username: json['username'] as String,
        deviceKeyId: json['deviceKeyId'] as String,
        trustTier: TrustTier.values.byName(json['trustTier'] as String),
        issuedAt: DateTime.parse(json['issuedAt'] as String),
        expiresAt: DateTime.parse(json['expiresAt'] as String),
      );

  /// Opaque bearer token.
  final String token;

  /// User.
  final String userId;

  /// Username.
  final String username;

  /// The key that signed in.
  final String deviceKeyId;

  /// That key's trust tier (a real server could gate features on it).
  final TrustTier trustTier;

  /// Issue time.
  final DateTime issuedAt;

  /// Expiry.
  final DateTime expiresAt;

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'token': token,
        'userId': userId,
        'username': username,
        'deviceKeyId': deviceKeyId,
        'trustTier': trustTier.name,
        'issuedAt': issuedAt.toUtc().toIso8601String(),
        'expiresAt': expiresAt.toUtc().toIso8601String(),
      };
}

/// Machine-readable rejection codes in `{"ok": false, "error": …}`.
abstract final class ServerErrors {
  /// Malformed request.
  static const String badRequest = 'bad_request';

  /// The username is taken.
  static const String usernameTaken = 'username_taken';

  /// No such user.
  static const String unknownUser = 'unknown_user';

  /// The challenge is unknown, expired, used, or for another purpose/user.
  static const String challenge = 'challenge_rejected';

  /// Attestation required but none was (or can be) provided.
  static const String attestationRequired = 'attestation_required';

  /// The attestation chain failed verification.
  static const String attestationFailed = 'attestation_failed';

  /// The public key is malformed or of an unsupported type.
  static const String badKey = 'unsupported_key';

  /// This public key is already registered.
  static const String keyReused = 'key_already_registered';

  /// The device key is unknown, not the user's, superseded or unbound.
  static const String deviceInactive = 'device_inactive';

  /// The signature does not verify.
  static const String badSignature = 'bad_signature';

  /// Wrong recovery code.
  static const String badRecoveryCode = 'bad_recovery_code';
}

const String _crockford = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/// A one-time recovery code: 12 Crockford base32 characters (60 random
/// bits) in groups of four, e.g. `7K2M-Q9XA-4RTP`.
String generateRecoveryCode() {
  final bytes = secureRandomBytes(12);
  final chars = [for (final b in bytes) _crockford[b & 31]];
  return [
    for (var i = 0; i < chars.length; i += 4) chars.sublist(i, i + 4).join(),
  ].join('-');
}

/// Upper-cases a typed code, drops spaces and dashes, and maps look-alike
/// letters (O → 0, I/L → 1).
String normalizeRecoveryCode(String input) => input
    .toUpperCase()
    .replaceAll(RegExp(r'[\s-]'), '')
    .replaceAll('O', '0')
    .replaceAll(RegExp('[IL]'), '1');

/// Salted SHA-256 of a recovery code, hex. A high-entropy random code makes
/// a fast hash acceptable here; a password would need a slow KDF.
String hashRecoveryCode(String saltHex, String code) =>
    sha256Hex(utf8.encode('$saltHex:${normalizeRecoveryCode(code)}'));
