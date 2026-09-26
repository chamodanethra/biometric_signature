import 'package:examples_shared/attestation.dart';

/// The Android applicationId of this app: what a genuine attestation names
/// in `attestationApplicationId`.
const String attestedPackageName = 'com.example.passwordless_login_example';

/// The mock server's registration and login policy. Editable in the server
/// console and persisted with the server's records.
class ServerPolicy {
  /// Creates a policy. The defaults are the strict ones.
  const ServerPolicy({
    this.requireAttestation = true,
    this.allowedSecurityLevels = const {
      SecurityLevel.trustedEnvironment,
      SecurityLevel.strongBox,
    },
    this.expectedPackage = attestedPackageName,
    this.requireLockedBootloader = false,
    this.registrationChallengeTtl = const Duration(minutes: 5),
    this.loginNonceTtl = const Duration(minutes: 2),
    this.sessionTtl = const Duration(minutes: 15),
  });

  /// Restores a policy from [toJson]; missing fields take their defaults.
  factory ServerPolicy.fromJson(Map<String, dynamic> json) {
    const d = ServerPolicy();
    Duration seconds(String key, Duration fallback) =>
        json[key] is int ? Duration(seconds: json[key] as int) : fallback;
    return ServerPolicy(
      requireAttestation:
          json['requireAttestation'] as bool? ?? d.requireAttestation,
      allowedSecurityLevels: json['allowedSecurityLevels'] is List
          ? {
              for (final l in json['allowedSecurityLevels'] as List)
                SecurityLevel.values.byName(l as String),
            }
          : d.allowedSecurityLevels,
      expectedPackage: json.containsKey('expectedPackage')
          ? json['expectedPackage'] as String?
          : d.expectedPackage,
      requireLockedBootloader:
          json['requireLockedBootloader'] as bool? ?? d.requireLockedBootloader,
      registrationChallengeTtl: seconds(
          'registrationChallengeTtlSeconds', d.registrationChallengeTtl),
      loginNonceTtl: seconds('loginNonceTtlSeconds', d.loginNonceTtl),
      sessionTtl: seconds('sessionTtlSeconds', d.sessionTtl),
    );
  }

  /// Reject registrations without a verified Android key attestation.
  ///
  /// On (default): iOS, macOS and Windows cannot register, because they
  /// have no per-key attestation. Off: they register with trust tier
  /// "Not attested", and an Android chain that fails verification is
  /// accepted as "Untrusted" instead of being rejected.
  final bool requireAttestation;

  /// Key security levels accepted from an attestation (never `Software`).
  final Set<SecurityLevel> allowedSecurityLevels;

  /// Package name the attestation must name, or `null` to only report it.
  final String? expectedPackage;

  /// Fail (instead of warn) on an unlocked bootloader or unverified boot.
  final bool requireLockedBootloader;

  /// How long a registration or recovery attestation challenge stays
  /// valid. It is consumed only when the registration succeeds, so a
  /// failed upload can be retried with the same key within this window.
  final Duration registrationChallengeTtl;

  /// How long a login nonce stays valid. Consumed on first use.
  final Duration loginNonceTtl;

  /// Session lifetime.
  final Duration sessionTtl;

  /// The attestation-verifier policy this maps to.
  AttestationPolicy toAttestationPolicy() => AttestationPolicy(
        expectedPackageName: expectedPackage,
        requireLockedBootloader: requireLockedBootloader,
        allowedSecurityLevels: allowedSecurityLevels,
      );

  /// Copy with changes. Pass [clearExpectedPackage] to stop checking the
  /// package name.
  ServerPolicy copyWith({
    bool? requireAttestation,
    Set<SecurityLevel>? allowedSecurityLevels,
    String? expectedPackage,
    bool clearExpectedPackage = false,
    bool? requireLockedBootloader,
    Duration? registrationChallengeTtl,
    Duration? loginNonceTtl,
    Duration? sessionTtl,
  }) =>
      ServerPolicy(
        requireAttestation: requireAttestation ?? this.requireAttestation,
        allowedSecurityLevels:
            allowedSecurityLevels ?? this.allowedSecurityLevels,
        expectedPackage: clearExpectedPackage
            ? null
            : expectedPackage ?? this.expectedPackage,
        requireLockedBootloader:
            requireLockedBootloader ?? this.requireLockedBootloader,
        registrationChallengeTtl:
            registrationChallengeTtl ?? this.registrationChallengeTtl,
        loginNonceTtl: loginNonceTtl ?? this.loginNonceTtl,
        sessionTtl: sessionTtl ?? this.sessionTtl,
      );

  /// One line for the audit log.
  String describe() => [
        'requireAttestation=$requireAttestation',
        'levels=${allowedSecurityLevels.map((l) => l.label).join('+')}',
        'package=${expectedPackage ?? '(not checked)'}',
        'lockedBootloader=${requireLockedBootloader ? 'required' : 'warn'}',
        'nonceTtl=${loginNonceTtl.inSeconds}s',
      ].join(', ');

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'requireAttestation': requireAttestation,
        'allowedSecurityLevels': [
          for (final l in allowedSecurityLevels) l.name,
        ],
        'expectedPackage': expectedPackage,
        'requireLockedBootloader': requireLockedBootloader,
        'registrationChallengeTtlSeconds': registrationChallengeTtl.inSeconds,
        'loginNonceTtlSeconds': loginNonceTtl.inSeconds,
        'sessionTtlSeconds': sessionTtl.inSeconds,
      };
}
