/// The bank's step-up policy: which signature a transfer needs.
library;

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';

import '../money.dart';
import 'models.dart';

/// Tier limits and verification rules. Editable in the server console.
class RiskPolicy {
  /// Creates a policy. Defaults: A ≤ $100, B ≤ $2,000, C above, and tier C
  /// needs an approval key attested as biometric-only.
  const RiskPolicy({
    this.tierALimitCents = 10000,
    this.tierBLimitCents = 200000,
    this.requireAttestedBiometricOnlyForTierC = true,
    this.maxClockSkewSeconds = 60,
    this.approvalTtlSeconds = 120,
  });

  /// Restores a policy from [toJson]; missing fields take defaults.
  factory RiskPolicy.fromJson(Map<String, dynamic> json) {
    const d = RiskPolicy();
    return RiskPolicy(
      tierALimitCents: json['tierALimitCents'] as int? ?? d.tierALimitCents,
      tierBLimitCents: json['tierBLimitCents'] as int? ?? d.tierBLimitCents,
      requireAttestedBiometricOnlyForTierC:
          json['requireAttestedBiometricOnlyForTierC'] as bool? ??
              d.requireAttestedBiometricOnlyForTierC,
      maxClockSkewSeconds:
          json['maxClockSkewSeconds'] as int? ?? d.maxClockSkewSeconds,
      approvalTtlSeconds:
          json['approvalTtlSeconds'] as int? ?? d.approvalTtlSeconds,
    );
  }

  /// Largest tier A amount (silent device-binding signature).
  final int tierALimitCents;

  /// Largest tier B amount (biometric approval). Above is tier C.
  final int tierBLimitCents;

  /// Tier C needs an approval key whose Android attestation proves
  /// hardware-enforced biometric-only use. When `false`, an unattested key
  /// declared biometric-only is accepted ("declared, unverified").
  final bool requireAttestedBiometricOnlyForTierC;

  /// Allowed difference between a request's timestamp and the bank's clock.
  final int maxClockSkewSeconds;

  /// How long an issued transfer payload can be approved.
  final int approvalTtlSeconds;

  /// The tier for [amountCents].
  RiskTier tierFor(int amountCents) {
    if (amountCents <= tierALimitCents) return RiskTier.a;
    if (amountCents <= tierBLimitCents) return RiskTier.b;
    return RiskTier.c;
  }

  /// Short rule text for [tier], e.g. `≤ $100`.
  String rangeFor(RiskTier tier) => switch (tier) {
        RiskTier.a => '≤ ${formatCents(tierALimitCents)}',
        RiskTier.b => '≤ ${formatCents(tierBLimitCents)}',
        RiskTier.c => '> ${formatCents(tierBLimitCents)}',
      };

  /// What [tier] requires, in words.
  String requirementFor(RiskTier tier) => switch (tier) {
        RiskTier.a =>
          'Silent signature by device_binding (no prompt): proves possession '
              'of this device only',
        RiskTier.b => 'Biometric approval signed by txn_approval',
        RiskTier.c => requireAttestedBiometricOnlyForTierC
            ? 'Biometric approval by txn_approval, and its attestation must '
                'prove a biometric-only key'
            : 'Biometric approval by txn_approval (attestation not required '
                'by the current policy)',
      };

  /// Decides whether [device] may make a transfer of [amountCents].
  ///
  /// The client runs the same function on the policy and device record the
  /// server sent, to preview the tier; the server's decision is final.
  TierDecision evaluate(int amountCents, DeviceRecord? device) {
    final tier = tierFor(amountCents);
    final requirement = requirementFor(tier);
    TierDecision deny(String reason) => TierDecision(
        tier: tier,
        allowed: false,
        requirement: requirement,
        assurance: 'None',
        reason: reason);

    if (device == null || !device.isActive) {
      return deny('This device is not bound to the bank.');
    }
    if (!device.deviceKey.isActive) {
      return deny('The device-binding key was revoked.');
    }
    if (tier == RiskTier.a) {
      return TierDecision(
        tier: tier,
        allowed: true,
        requirement: requirement,
        assurance: 'Device possession only (silent key, no user check)',
      );
    }
    final key = device.activeApprovalKey;
    if (key == null) {
      return deny('No active approval key: re-verify to register a new one.');
    }
    if (tier == RiskTier.b) {
      return TierDecision(
        tier: tier,
        allowed: true,
        requirement: requirement,
        assurance: key.authPolicySummary,
      );
    }
    if (key.attestedBiometricOnly) {
      return TierDecision(
        tier: tier,
        allowed: true,
        requirement: requirement,
        assurance: 'Biometric only, proven by hardware key attestation',
      );
    }
    if (!requireAttestedBiometricOnlyForTierC &&
        key.attestedUserAuthType == null &&
        key.declaredUseDeviceCredentials == false) {
      return TierDecision(
        tier: tier,
        allowed: true,
        requirement: requirement,
        assurance: 'Biometric only as declared by the app, not verified '
            '(attestation not required by policy)',
      );
    }
    return deny('Capped at tier B: ${whyNotBiometricOnly(device, key)} '
        'Transfers over ${formatCents(tierBLimitCents)} are declined on this '
        'device.');
  }

  /// Why [key] does not qualify for tier C.
  String whyNotBiometricOnly(DeviceRecord device, RegisteredKey key) {
    final type = key.attestedUserAuthType;
    if (type != null && type != 2) {
      return 'the approval key is attested as '
          '${type == 3 ? 'biometric OR device PIN' : 'userAuthType $type'}, '
          'and tier C needs biometric-only.';
    }
    if (key.declaredUseDeviceCredentials == true) {
      return 'the approval key allows a device PIN/passcode fallback, and '
          'tier C needs biometric-only.';
    }
    return switch (key.trustTier) {
      TrustTier.untrusted =>
        'the approval key\'s attestation failed verification, so the bank '
            'cannot tell how the key is protected.',
      TrustTier.none => switch (device.platform) {
          DevicePlatform.android =>
            'this device\'s keystore could not attest the approval key.',
          DevicePlatform.ios ||
          DevicePlatform.macos =>
            '${device.platform.label} has no per-key attestation, so the '
                'bank cannot verify the key is biometric-only.',
          DevicePlatform.windows =>
            'Windows Hello keys are not attested by this plugin.',
          DevicePlatform.other => 'the key is not attested.',
        },
      TrustTier.tee ||
      TrustTier.strongBox =>
        'the attestation does not prove a biometric-only key.',
    };
  }

  /// Copy with changes.
  RiskPolicy copyWith({
    int? tierALimitCents,
    int? tierBLimitCents,
    bool? requireAttestedBiometricOnlyForTierC,
    int? maxClockSkewSeconds,
    int? approvalTtlSeconds,
  }) =>
      RiskPolicy(
        tierALimitCents: tierALimitCents ?? this.tierALimitCents,
        tierBLimitCents: tierBLimitCents ?? this.tierBLimitCents,
        requireAttestedBiometricOnlyForTierC:
            requireAttestedBiometricOnlyForTierC ??
                this.requireAttestedBiometricOnlyForTierC,
        maxClockSkewSeconds: maxClockSkewSeconds ?? this.maxClockSkewSeconds,
        approvalTtlSeconds: approvalTtlSeconds ?? this.approvalTtlSeconds,
      );

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'tierALimitCents': tierALimitCents,
        'tierBLimitCents': tierBLimitCents,
        'requireAttestedBiometricOnlyForTierC':
            requireAttestedBiometricOnlyForTierC,
        'maxClockSkewSeconds': maxClockSkewSeconds,
        'approvalTtlSeconds': approvalTtlSeconds,
      };
}

/// The outcome of [RiskPolicy.evaluate].
class TierDecision {
  /// Creates a decision.
  const TierDecision({
    required this.tier,
    required this.allowed,
    required this.requirement,
    required this.assurance,
    this.reason,
  });

  /// Restores a decision from [toJson].
  factory TierDecision.fromJson(Map<String, dynamic> json) => TierDecision(
        tier: RiskTier.fromLabel(json['tier']),
        allowed: json['allowed'] as bool,
        requirement: json['requirement'] as String,
        assurance: json['assurance'] as String,
        reason: json['reason'] as String?,
      );

  /// The tier.
  final RiskTier tier;

  /// Whether the device may make this transfer.
  final bool allowed;

  /// What the tier requires.
  final String requirement;

  /// What the bank will actually know about the user's involvement.
  final String assurance;

  /// Why it is not allowed.
  final String? reason;

  /// The key that must sign.
  String get requiredAlias => tier.requiredAlias;

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'tier': tier.label,
        'allowed': allowed,
        'requirement': requirement,
        'assurance': assurance,
        'reason': reason,
      };
}
