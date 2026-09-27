/// Records kept by the mock bank server. They are JSON-serializable because
/// the server persists them and sends some of them over the (mock) wire.
library;

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';

/// The two key aliases this app creates. Aliases are limited to
/// `[a-z0-9_-]` (Windows and Android use them in storage keys and files).
abstract final class KeyAliases {
  /// Silent, device-bound key (`requireAuthentication: false`). Signs every
  /// API request and tier A transfers. Proves possession of this device only.
  static const String deviceBinding = 'device_binding';

  /// Biometric approval key (`enforceBiometric: true`,
  /// `setInvalidatedByBiometricEnrollment: true`). Signs tier B and C
  /// transfers.
  static const String approval = 'txn_approval';
}

/// Risk tier of a transfer, decided by the server's `RiskPolicy`.
enum RiskTier {
  /// Small amounts: a silent `device_binding` signature is enough.
  a('A'),

  /// Medium amounts: biometric approval with `txn_approval`.
  b('B'),

  /// Large amounts: `txn_approval`, attested biometric-only.
  c('C');

  const RiskTier(this.label);

  /// `A`, `B` or `C`.
  final String label;

  /// The key alias whose signature the tier requires.
  String get requiredAlias =>
      this == RiskTier.a ? KeyAliases.deviceBinding : KeyAliases.approval;

  /// Parses [label]; throws [FormatException] for anything else.
  static RiskTier fromLabel(Object? label) {
    for (final t in values) {
      if (t.label == label) return t;
    }
    throw FormatException('Unknown risk tier $label');
  }
}

/// One step of a server-side verification, shown in traces and receipts.
class ServerCheck {
  /// Creates a check.
  const ServerCheck({
    required this.id,
    required this.title,
    required this.status,
    required this.detail,
  });

  /// A passing check.
  const ServerCheck.pass(this.id, this.title, this.detail)
      : status = CheckStatus.pass;

  /// A failing check.
  const ServerCheck.fail(this.id, this.title, this.detail)
      : status = CheckStatus.fail;

  /// A warning (accepted, but flagged).
  const ServerCheck.warn(this.id, this.title, this.detail)
      : status = CheckStatus.warn;

  /// Information only.
  const ServerCheck.info(this.id, this.title, this.detail)
      : status = CheckStatus.info;

  /// Restores a check from [toJson].
  factory ServerCheck.fromJson(Map<String, dynamic> json) => ServerCheck(
        id: json['id'] as String,
        title: json['title'] as String,
        status: CheckStatus.values.byName(json['status'] as String),
        detail: json['detail'] as String,
      );

  /// Stable identifier, e.g. `request.signature`.
  final String id;

  /// Short title.
  final String title;

  /// Result.
  final CheckStatus status;

  /// Explanation with concrete values.
  final String detail;

  /// Whether the check failed.
  bool get failed => status == CheckStatus.fail;

  /// JSON form.
  Map<String, dynamic> toJson() =>
      {'id': id, 'title': title, 'status': status.name, 'detail': detail};

  /// Parses a JSON list of checks (missing → empty).
  static List<ServerCheck> listFromJson(Object? json) => [
        for (final c in (json as List<dynamic>? ?? const []))
          ServerCheck.fromJson(c as Map<String, dynamic>),
      ];

  @override
  String toString() => '[${status.name}] $title: $detail';
}

/// A bank account.
class Account {
  /// Creates an account.
  const Account({
    required this.id,
    required this.name,
    required this.customerId,
    required this.balanceCents,
  });

  /// Restores an account from [toJson].
  factory Account.fromJson(Map<String, dynamic> json) => Account(
        id: json['id'] as String,
        name: json['name'] as String,
        customerId: json['customerId'] as String,
        balanceCents: json['balanceCents'] as int,
      );

  /// Account id, e.g. `CHK-4821`.
  final String id;

  /// Display name.
  final String name;

  /// Owner.
  final String customerId;

  /// Balance in cents.
  final int balanceCents;

  /// Copy with a new balance.
  Account withBalance(int cents) =>
      Account(id: id, name: name, customerId: customerId, balanceCents: cents);

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'customerId': customerId,
        'balanceCents': balanceCents,
      };
}

/// A saved payee.
class Payee {
  /// Creates a payee.
  const Payee({required this.id, required this.name, required this.account});

  /// Restores a payee from [toJson].
  factory Payee.fromJson(Map<String, dynamic> json) => Payee(
        id: json['id'] as String,
        name: json['name'] as String,
        account: json['account'] as String,
      );

  /// Payee id.
  final String id;

  /// Display name.
  final String name;

  /// Masked account number, e.g. `••3310`.
  final String account;

  /// JSON form.
  Map<String, dynamic> toJson() => {'id': id, 'name': name, 'account': account};
}

/// One ledger line (a debit is negative).
class Posting {
  /// Creates a posting.
  const Posting({
    required this.id,
    required this.time,
    required this.accountId,
    required this.amountCents,
    required this.description,
    required this.balanceAfterCents,
    this.txnId,
    this.tier,
  });

  /// Restores a posting from [toJson].
  factory Posting.fromJson(Map<String, dynamic> json) => Posting(
        id: json['id'] as String,
        time: DateTime.parse(json['time'] as String),
        accountId: json['accountId'] as String,
        amountCents: json['amountCents'] as int,
        description: json['description'] as String,
        balanceAfterCents: json['balanceAfterCents'] as int,
        txnId: json['txnId'] as String?,
        tier: json['tier'] == null ? null : RiskTier.fromLabel(json['tier']),
      );

  /// Posting id.
  final String id;

  /// When it was posted.
  final DateTime time;

  /// Account debited or credited.
  final String accountId;

  /// Signed amount in cents.
  final int amountCents;

  /// Description.
  final String description;

  /// Account balance after this posting.
  final int balanceAfterCents;

  /// The transfer that caused it, if any.
  final String? txnId;

  /// The transfer's risk tier, if any.
  final RiskTier? tier;

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'id': id,
        'time': time.toUtc().toIso8601String(),
        'accountId': accountId,
        'amountCents': amountCents,
        'description': description,
        'balanceAfterCents': balanceAfterCents,
        'txnId': txnId,
        'tier': tier?.label,
      };
}

/// Lifecycle of a registered key.
enum KeyStatus {
  /// Accepted for new signatures.
  active,

  /// No longer accepted (rotated, unbound or replaced).
  revoked,
}

/// A public key the server registered for a device, with the evidence it
/// had at registration time.
class RegisteredKey {
  /// Creates a record.
  RegisteredKey({
    required this.alias,
    required this.publicKey,
    required this.registeredAt,
    required this.attestation,
    this.declaredUseDeviceCredentials,
    this.status = KeyStatus.active,
    this.revokedAt,
    this.revokeReason,
  });

  /// Restores a record from [toJson].
  factory RegisteredKey.fromJson(Map<String, dynamic> json) => RegisteredKey(
        alias: json['alias'] as String,
        publicKey: json['publicKey'] as String,
        registeredAt: DateTime.parse(json['registeredAt'] as String),
        attestation: AttestationReport.fromJson(
            json['attestation'] as Map<String, dynamic>),
        declaredUseDeviceCredentials:
            json['declaredUseDeviceCredentials'] as bool?,
        status: KeyStatus.values.byName(json['status'] as String),
        revokedAt: json['revokedAt'] == null
            ? null
            : DateTime.parse(json['revokedAt'] as String),
        revokeReason: json['revokeReason'] as String?,
      );

  /// Alias on the device.
  final String alias;

  /// SPKI DER, base64 (the plugin's `publicKey`).
  final String publicKey;

  /// Registration time.
  final DateTime registeredAt;

  /// The server's attestation verdict (`notProvided` off Android).
  final AttestationReport attestation;

  /// `useDeviceCredentials` as declared by the app (unverified unless
  /// attested).
  final bool? declaredUseDeviceCredentials;

  /// Status.
  KeyStatus status;

  /// When it was revoked.
  DateTime? revokedAt;

  /// Why it was revoked.
  String? revokeReason;

  late final ParsedPublicKey _parsed = ParsedPublicKey.parse(publicKey);

  /// SHA-256 of the SPKI, hex.
  String get fingerprint => _parsed.fingerprint;

  /// e.g. `EC P-256` or `RSA 2048`.
  String get description => _parsed.description;

  /// Whether signatures are accepted.
  bool get isActive => status == KeyStatus.active;

  /// Trust tier from the attestation.
  TrustTier get trustTier => attestation.trustTier;

  /// Attestation proves hardware-enforced biometric-only use.
  bool get attestedBiometricOnly => attestation.attestsBiometricOnly;

  /// Attested hardware-enforced `userAuthType` (only when verified).
  int? get attestedUserAuthType => attestation.passed
      ? attestation.keyDescription?.hardwareEnforced.userAuthType
      : null;

  /// Attested `noAuthRequired` (only when verified).
  bool? get attestedNoAuthRequired => attestation.passed
      ? (attestation.keyDescription!.hardwareEnforced.noAuthRequired ||
          attestation.keyDescription!.softwareEnforced.noAuthRequired)
      : null;

  /// Whether the key is supposed to be biometric-only: attested as such,
  /// or (unattested) declared without a device-credential fallback.
  bool get expectedBiometricOnly {
    final attestedType = attestedUserAuthType;
    if (attestedType != null) return attestedType == 2;
    return declaredUseDeviceCredentials == false;
  }

  /// One-line description of what the server knows about the key's
  /// authentication policy.
  String get authPolicySummary {
    if (attestedNoAuthRequired == true) {
      return 'No user authentication (attested noAuthRequired)';
    }
    final attestedType = attestedUserAuthType;
    if (attestedType != null) {
      return switch (attestedType) {
        2 => 'Biometric only (attested, userAuthType 2)',
        3 => 'Biometric or device PIN (attested, userAuthType 3)',
        1 => 'Device PIN only (attested, userAuthType 1)',
        _ => 'userAuthType $attestedType (attested)',
      };
    }
    if (alias == KeyAliases.deviceBinding) {
      return 'No user authentication (declared, unverified)';
    }
    return switch (declaredUseDeviceCredentials) {
      false => 'Biometric only (declared, unverified)',
      true => 'Biometric or device PIN (declared, unverified)',
      null => 'Unknown',
    };
  }

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'alias': alias,
        'publicKey': publicKey,
        'registeredAt': registeredAt.toUtc().toIso8601String(),
        'attestation': attestation.toJson(),
        'declaredUseDeviceCredentials': declaredUseDeviceCredentials,
        'status': status.name,
        'revokedAt': revokedAt?.toUtc().toIso8601String(),
        'revokeReason': revokeReason,
      };
}

/// Lifecycle of a device binding.
enum DeviceStatus {
  /// Bound and accepted.
  active,

  /// The user unbound it.
  unbound,

  /// A later enrollment from the same app install replaced it.
  replaced,
}

/// A bound device: its request-signing key and its approval keys.
class DeviceRecord {
  /// Creates a record.
  DeviceRecord({
    required this.deviceId,
    required this.customerId,
    required this.platform,
    required this.enrolledAt,
    required this.deviceKey,
    required List<RegisteredKey> approvalKeys,
    this.status = DeviceStatus.active,
  }) : approvalKeys = List.of(approvalKeys);

  /// Restores a record from [toJson].
  factory DeviceRecord.fromJson(Map<String, dynamic> json) => DeviceRecord(
        deviceId: json['deviceId'] as String,
        customerId: json['customerId'] as String,
        platform: DevicePlatform.fromName(json['platform'] as String?),
        enrolledAt: DateTime.parse(json['enrolledAt'] as String),
        deviceKey:
            RegisteredKey.fromJson(json['deviceKey'] as Map<String, dynamic>),
        approvalKeys: [
          for (final k in json['approvalKeys'] as List<dynamic>)
            RegisteredKey.fromJson(k as Map<String, dynamic>),
        ],
        status: DeviceStatus.values.byName(json['status'] as String),
      );

  /// Server-assigned id.
  final String deviceId;

  /// Owner.
  final String customerId;

  /// Platform the app declared at enrollment.
  final DevicePlatform platform;

  /// Enrollment time.
  final DateTime enrolledAt;

  /// The `device_binding` key.
  final RegisteredKey deviceKey;

  /// Every `txn_approval` key ever registered, oldest first.
  final List<RegisteredKey> approvalKeys;

  /// Status.
  DeviceStatus status;

  /// Whether the device may make requests.
  bool get isActive => status == DeviceStatus.active;

  /// The approval key accepted today, if any.
  RegisteredKey? get activeApprovalKey {
    for (final k in approvalKeys.reversed) {
      if (k.isActive) return k;
    }
    return null;
  }

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'deviceId': deviceId,
        'customerId': customerId,
        'platform': platform.name,
        'enrolledAt': enrolledAt.toUtc().toIso8601String(),
        'deviceKey': deviceKey.toJson(),
        'approvalKeys': [for (final k in approvalKeys) k.toJson()],
        'status': status.name,
      };
}

/// Outcome of a transfer confirmation.
enum TransferStatus {
  /// Verified and posted.
  accepted,

  /// Rejected by a check.
  rejected,
}

/// A decided transfer, with the full verification trace.
class TransferRecord {
  /// Creates a record.
  const TransferRecord({
    required this.txnId,
    required this.deviceId,
    required this.amountCents,
    required this.currency,
    required this.fromAccount,
    required this.payee,
    required this.tier,
    required this.status,
    required this.signer,
    required this.authenticationType,
    required this.anomaly,
    required this.checks,
    required this.decidedAt,
    this.reason,
    this.balanceAfterCents,
  });

  /// Restores a record from [toJson].
  factory TransferRecord.fromJson(Map<String, dynamic> json) => TransferRecord(
        txnId: json['txnId'] as String,
        deviceId: json['deviceId'] as String,
        amountCents: json['amountCents'] as int,
        currency: json['currency'] as String,
        fromAccount: json['fromAccount'] as String,
        payee: json['payee'] as String,
        tier: RiskTier.fromLabel(json['tier']),
        status: TransferStatus.values.byName(json['status'] as String),
        signer: json['signer'] as String?,
        authenticationType: json['authenticationType'] as String?,
        anomaly: json['anomaly'] as bool? ?? false,
        checks: ServerCheck.listFromJson(json['checks']),
        decidedAt: DateTime.parse(json['decidedAt'] as String),
        reason: json['reason'] as String?,
        balanceAfterCents: json['balanceAfterCents'] as int?,
      );

  /// Transaction id.
  final String txnId;

  /// Device that confirmed it.
  final String deviceId;

  /// Amount from the issued payload.
  final int amountCents;

  /// Currency.
  final String currency;

  /// Debited account.
  final String fromAccount;

  /// Payee name.
  final String payee;

  /// Risk tier.
  final RiskTier tier;

  /// Accepted or rejected.
  final TransferStatus status;

  /// Alias the client said it signed with.
  final String? signer;

  /// `authenticationType` the client reported (unsigned).
  final String? authenticationType;

  /// Whether the reported authentication type contradicts the key.
  final bool anomaly;

  /// The verification trace.
  final List<ServerCheck> checks;

  /// Decision time.
  final DateTime decidedAt;

  /// Rejection reason.
  final String? reason;

  /// Balance after posting (accepted only).
  final int? balanceAfterCents;

  /// Whether it was accepted.
  bool get accepted => status == TransferStatus.accepted;

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'txnId': txnId,
        'deviceId': deviceId,
        'amountCents': amountCents,
        'currency': currency,
        'fromAccount': fromAccount,
        'payee': payee,
        'tier': tier.label,
        'status': status.name,
        'signer': signer,
        'authenticationType': authenticationType,
        'anomaly': anomaly,
        'checks': [for (final c in checks) c.toJson()],
        'decidedAt': decidedAt.toUtc().toIso8601String(),
        'reason': reason,
        'balanceAfterCents': balanceAfterCents,
      };
}
