import 'dart:convert';
import 'dart:typed_data';

import 'package:banking_app_example/server/bank_server.dart';
import 'package:banking_app_example/server/models.dart';
import 'package:banking_app_example/server/risk_policy.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/testing.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final synthetic = SyntheticAttestation();
  final registeredAt = DateTime.utc(2026, 9, 27);

  /// An approval key with a verified synthetic attestation.
  RegisteredKey attestedKey({required int userAuthType}) {
    final key = SoftwareEcKeyPair.generate();
    final challenge = List<int>.generate(32, (i) => i);
    final chain = synthetic.chainFor(
      attestedSpki: key.spki,
      challenge: challenge,
      properties: SyntheticKeyProperties(
        userAuthType: userAuthType,
        packageName: BankServer.androidPackageName,
      ),
    );
    final report = AttestationVerifier(
      trustedRootSpkiSha256: {synthetic.rootSpkiSha256},
      now: () => registeredAt,
    ).verify(
      chain: chain,
      expectedChallenge: challenge.toUint8List(),
      expectedPublicKey: base64.encode(key.spki),
      policy: const AttestationPolicy(
          expectedPackageName: BankServer.androidPackageName),
    );
    expect(report.passed, isTrue, reason: '${report.failures}');
    return RegisteredKey(
      alias: KeyAliases.approval,
      publicKey: base64.encode(key.spki),
      registeredAt: registeredAt,
      attestation: report,
      declaredUseDeviceCredentials: userAuthType != 2,
    );
  }

  RegisteredKey unattestedKey(String alias, {bool? useDeviceCredentials}) =>
      RegisteredKey(
        alias: alias,
        publicKey: base64.encode(SoftwareEcKeyPair.generate().spki),
        registeredAt: registeredAt,
        attestation: AttestationReport.notProvided('No attestation'),
        declaredUseDeviceCredentials: useDeviceCredentials,
      );

  RegisteredKey untrustedKey() => RegisteredKey(
        alias: KeyAliases.approval,
        publicKey: base64.encode(SoftwareEcKeyPair.generate().spki),
        registeredAt: registeredAt,
        attestation: AttestationReport(
          checks: const [
            AttestationCheck(
                id: AttestationCheckIds.chainRoot,
                title: 'Root',
                status: CheckStatus.fail,
                detail: 'software root'),
          ],
          trustTier: TrustTier.untrusted,
          verifiedAt: registeredAt,
        ),
        declaredUseDeviceCredentials: false,
      );

  DeviceRecord device(DevicePlatform platform, RegisteredKey? approval) =>
      DeviceRecord(
        deviceId: 'dev-test',
        customerId: 'cust-alex',
        platform: platform,
        enrolledAt: registeredAt,
        deviceKey: unattestedKey(KeyAliases.deviceBinding),
        approvalKeys: [if (approval != null) approval],
      );

  const policy = RiskPolicy();

  group('tierFor', () {
    test('default boundaries: A ≤ \$100 < B ≤ \$2,000 < C', () {
      expect(policy.tierFor(1), RiskTier.a);
      expect(policy.tierFor(10000), RiskTier.a);
      expect(policy.tierFor(10001), RiskTier.b);
      expect(policy.tierFor(200000), RiskTier.b);
      expect(policy.tierFor(200001), RiskTier.c);
    });

    test('custom limits', () {
      final p = policy.copyWith(tierALimitCents: 5000, tierBLimitCents: 100000);
      expect(p.tierFor(5001), RiskTier.b);
      expect(p.tierFor(100001), RiskTier.c);
      expect(p.rangeFor(RiskTier.c), r'> $1,000.00');
    });

    test('tiers map to the key they require', () {
      expect(RiskTier.a.requiredAlias, KeyAliases.deviceBinding);
      expect(RiskTier.b.requiredAlias, KeyAliases.approval);
      expect(RiskTier.c.requiredAlias, KeyAliases.approval);
    });
  });

  group('evaluate', () {
    late RegisteredKey bioOnly;
    late RegisteredKey bioOrPin;
    setUpAll(() {
      bioOnly = attestedKey(userAuthType: 2);
      bioOrPin = attestedKey(userAuthType: 3);
    });

    test('tier A needs only an active device key', () {
      final d = policy.evaluate(4500, device(DevicePlatform.ios, null));
      expect(d.allowed, isTrue);
      expect(d.assurance, contains('possession only'));
    });

    test('tier B needs an active approval key', () {
      expect(policy.evaluate(125000, device(DevicePlatform.ios, null)).allowed,
          isFalse);
      final ios =
          unattestedKey(KeyAliases.approval, useDeviceCredentials: false);
      final d = policy.evaluate(125000, device(DevicePlatform.ios, ios));
      expect(d.allowed, isTrue);
      expect(d.assurance, 'Biometric only (declared, unverified)');
    });

    test('a revoked approval key cannot approve', () {
      final key = unattestedKey(KeyAliases.approval)
        ..status = KeyStatus.revoked;
      expect(policy.evaluate(125000, device(DevicePlatform.ios, key)).allowed,
          isFalse);
    });

    test('tier C accepts an approval key attested biometric-only', () {
      expect(bioOnly.attestedBiometricOnly, isTrue);
      final d =
          policy.evaluate(240000, device(DevicePlatform.android, bioOnly));
      expect(d.allowed, isTrue);
      expect(d.assurance, contains('hardware key attestation'));
    });

    test('tier C declines a key attested biometric-or-PIN (userAuthType 3)',
        () {
      expect(bioOrPin.attestedUserAuthType, 3);
      final d =
          policy.evaluate(240000, device(DevicePlatform.android, bioOrPin));
      expect(d.allowed, isFalse);
      expect(d.reason, contains('biometric OR device PIN'));
      // Even with attestation not required: the attestation proves a PIN
      // fallback.
      final lax = policy.copyWith(requireAttestedBiometricOnlyForTierC: false);
      expect(
          lax
              .evaluate(240000, device(DevicePlatform.android, bioOrPin))
              .allowed,
          isFalse);
    });

    test('iOS is capped at tier B while attestation is required', () {
      final key =
          unattestedKey(KeyAliases.approval, useDeviceCredentials: false);
      final d = policy.evaluate(240000, device(DevicePlatform.ios, key));
      expect(d.allowed, isFalse);
      expect(d.reason, startsWith('Capped at tier B'));
      expect(d.reason, contains('iOS has no per-key attestation'));
      final w = policy.evaluate(240000, device(DevicePlatform.windows, key));
      expect(w.reason, contains('Windows Hello'));
    });

    test('with the toggle off, tier C accepts "declared, unverified"', () {
      final lax = policy.copyWith(requireAttestedBiometricOnlyForTierC: false);
      final declaredBio =
          unattestedKey(KeyAliases.approval, useDeviceCredentials: false);
      final d = lax.evaluate(240000, device(DevicePlatform.ios, declaredBio));
      expect(d.allowed, isTrue);
      expect(d.assurance, contains('not verified'));
      final declaredPin =
          unattestedKey(KeyAliases.approval, useDeviceCredentials: true);
      final p = lax.evaluate(240000, device(DevicePlatform.ios, declaredPin));
      expect(p.allowed, isFalse);
      expect(p.reason, contains('PIN/passcode fallback'));
    });

    test('a failed attestation cannot reach tier C', () {
      final d = policy.evaluate(
          240000, device(DevicePlatform.android, untrustedKey()));
      expect(d.allowed, isFalse);
      expect(d.reason, contains('failed verification'));
    });

    test('an unbound device can do nothing', () {
      final d = device(DevicePlatform.android, bioOnly)
        ..status = DeviceStatus.unbound;
      expect(policy.evaluate(100, d).allowed, isFalse);
      expect(policy.evaluate(100, null).allowed, isFalse);
    });
  });

  test('policy and decisions round-trip through JSON', () {
    final p = policy.copyWith(
        tierALimitCents: 25000, requireAttestedBiometricOnlyForTierC: false);
    final restored = RiskPolicy.fromJson(
        jsonDecode(jsonEncode(p.toJson())) as Map<String, dynamic>);
    expect(restored.toJson(), p.toJson());
    final d = policy.evaluate(240000, null);
    expect(TierDecision.fromJson(d.toJson()).toJson(), d.toJson());
  });

  test('device records round-trip, keeping attestation facts', () {
    final record = device(DevicePlatform.android, attestedKey(userAuthType: 2));
    final restored = DeviceRecord.fromJson(
        jsonDecode(jsonEncode(record.toJson())) as Map<String, dynamic>);
    expect(restored.activeApprovalKey!.attestedBiometricOnly, isTrue);
    expect(restored.activeApprovalKey!.fingerprint,
        record.activeApprovalKey!.fingerprint);
    expect(restored.deviceKey.trustTier, TrustTier.none);
  });
}

extension on List<int> {
  Uint8List toUint8List() => Uint8List.fromList(this);
}
