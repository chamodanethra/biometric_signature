import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/testing.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/attestation_fixtures.dart';
import 'support/fixtures.dart';

void main() {
  AttestationReport verifyFixture(
    AttestationFixture f, {
    Uint8List? challenge,
    String? publicKey,
    AttestationPolicy policy = const AttestationPolicy(),
    Set<String>? trusted,
    List<Uint8List>? chain,
  }) =>
      AttestationVerifier(trustedRootSpkiSha256: trusted, now: () => f.validAt)
          .verify(
        chain: chain ?? f.chain,
        expectedChallenge: challenge ?? f.challenge,
        expectedPublicKey: publicKey ?? f.leafPublicKey,
        policy: policy,
      );

  CheckStatus status(AttestationReport r, String id) => r.check(id)!.status;

  group('happy path', () {
    const expectedTier = {
      'akita/sdk34/TEE_EC_NONE': TrustTier.tee,
      'akita/sdk34/SB_RSA_NONE': TrustTier.strongBox,
      'akita/sdk34/TEE_RSA_NONE_USERAUTH': TrustTier.tee,
      'blueline/sdk28/SB_RSA_NONE_USERAUTH': TrustTier.strongBox,
      'blueline/sdk28/TEE_EC_NONE': TrustTier.tee,
      'walleye/sdk27/TEE_EC_NONE': TrustTier.tee,
      'caiman/sdk36/SB_EC_RKP': TrustTier.strongBox,
      'caiman/sdk36/TEE_EC_RKP': TrustTier.tee,
      'frankel/sdk37/TEE_EC_2026': TrustTier.tee,
      'tegu/sdk36/SB_EC_2026_ROOT': TrustTier.strongBox,
    };
    for (final entry in expectedTier.entries) {
      test(entry.key, () {
        final f = AttestationFixture(entry.key);
        final r = verifyFixture(f);
        expect(r.passed, isTrue, reason: r.failures.join('\n'));
        expect(r.trustTier, entry.value);
        expect(r.selectedCertificateIndex, 0);
        expect(r.keyDescription, isNotNull);
        expect(r.certificates, hasLength(f.chain.length));
        expect(status(r, AttestationCheckIds.revocation), CheckStatus.warn);
        expect(r.check(AttestationCheckIds.revocation)!.detail,
            contains('https://android.googleapis.com/attestation/status'));
      });
    }

    test('the challenge in the fixtures is "challenge" (base64 Y2hhbGxlbmdl)',
        () {
      final f = AttestationFixture('akita/sdk34/TEE_EC_NONE');
      expect(f.expected['attestationChallenge'], 'Y2hhbGxlbmdl');
      expect(utf8.decode(f.challenge), 'challenge');
    });

    test('the expected key may be PEM or hex', () {
      final f = AttestationFixture('caiman/sdk36/SB_EC_RKP');
      final spki = f.certificates.first.spkiRaw;
      expect(verifyFixture(f, publicKey: spkiToPem(spki)).passed, isTrue);
      expect(verifyFixture(f, publicKey: toHex(spki)).passed, isTrue);
    });

    test('verifyInIsolate gives the same result', () async {
      final f = AttestationFixture('tegu/sdk36/SB_EC_2026_ROOT');
      final r = await AttestationVerifier.verifyInIsolate(
        chain: f.chain,
        expectedChallenge: f.challenge,
        expectedPublicKey: f.leafPublicKey,
        now: f.validAt,
      );
      expect(r.passed, isTrue);
      expect(r.trustTier, TrustTier.strongBox);
    });
  });

  group('rejections', () {
    final f = AttestationFixture('akita/sdk34/TEE_EC_NONE');

    test('wrong challenge', () {
      final r = verifyFixture(f, challenge: utf8.encode('challengf'));
      expect(status(r, AttestationCheckIds.challenge), CheckStatus.fail);
      expect(r.passed, isFalse);
      expect(r.trustTier, TrustTier.untrusted);
    });

    test('wrong public key', () {
      final r = verifyFixture(f,
          publicKey: SoftwareEcKeyPair.generate().publicKey.base64);
      expect(status(r, AttestationCheckIds.publicKey), CheckStatus.fail);
      expect(r.passed, isFalse);
    });

    test('unparseable public key', () {
      final r = verifyFixture(f, publicKey: 'not a key');
      expect(status(r, AttestationCheckIds.publicKey), CheckStatus.fail);
    });

    test('an edited challenge inside the leaf breaks its signature', () {
      final leaf = Uint8List.fromList(f.chain.first);
      final needle = utf8.encode('challenge');
      final at = _indexOf(leaf, needle);
      expect(at, isNonNegative);
      leaf.setAll(at, utf8.encode('forged!!!'));
      final r = verifyFixture(
        f,
        chain: [leaf, ...f.chain.skip(1)],
        challenge: utf8.encode('forged!!!'),
      );
      expect(status(r, AttestationCheckIds.chainLinks), CheckStatus.fail);
      expect(status(r, AttestationCheckIds.challenge), CheckStatus.pass);
      expect(r.passed, isFalse);
      expect(r.trustTier, TrustTier.untrusted);
      expect(r.check(AttestationCheckIds.keyDescription)!.detail,
          contains('unverified claims'));
    });

    test('untrusted root', () {
      final r = verifyFixture(f, trusted: {});
      expect(status(r, AttestationCheckIds.chainRoot), CheckStatus.fail);
      expect(r.check(AttestationCheckIds.chainRoot)!.detail,
          contains('emulator/software attestation'));
      expect(r.trustTier, TrustTier.untrusted);
    });

    test('dropped root', () {
      final r = verifyFixture(f, chain: f.chain.sublist(0, 4));
      expect(r.passed, isFalse);
      expect(status(r, AttestationCheckIds.chainRoot), CheckStatus.fail);
    });

    test('unlocked bootloader: warning by default, failure by policy', () {
      expect(status(verifyFixture(f), AttestationCheckIds.bootState),
          CheckStatus.warn);
      final strict = verifyFixture(f,
          policy: const AttestationPolicy(requireLockedBootloader: true));
      expect(status(strict, AttestationCheckIds.bootState), CheckStatus.fail);
      expect(strict.passed, isFalse);
    });

    test('expected package name', () {
      const package =
          'com.google.wireless.android.security.attestationverifier.collector';
      final ok = verifyFixture(f,
          policy: const AttestationPolicy(expectedPackageName: package));
      expect(status(ok, AttestationCheckIds.application), CheckStatus.pass);
      final bad = verifyFixture(f,
          policy: const AttestationPolicy(expectedPackageName: 'com.evil'));
      expect(status(bad, AttestationCheckIds.application), CheckStatus.fail);
    });

    test('expected signing certificate digest', () {
      final digest =
          toHex(base64.decode('EDk47kU35Z6O55L2VFBPuDRvxrNG0LvEQV/DOfz8jsE='));
      final ok = verifyFixture(f,
          policy:
              AttestationPolicy(expectedSigningCertificateDigests: {digest}));
      expect(status(ok, AttestationCheckIds.application), CheckStatus.pass);
      final bad = verifyFixture(f,
          policy: const AttestationPolicy(
              expectedSigningCertificateDigests: {'00'}));
      expect(status(bad, AttestationCheckIds.application), CheckStatus.fail);
    });

    test('StrongBox-only policy rejects a TEE key', () {
      final r = verifyFixture(f,
          policy: const AttestationPolicy(
              allowedSecurityLevels: {SecurityLevel.strongBox}));
      expect(status(r, AttestationCheckIds.securityLevel), CheckStatus.fail);
    });

    test('tags out of order', () {
      final chain = certificatesFromPem(
          fixtureText('attestation/invalid/tags_not_in_ascending_order.pem'));
      final r = AttestationVerifier(now: () => DateTime.utc(2023)).verify(
          chain: chain,
          expectedChallenge: Uint8List(0),
          expectedPublicKey:
              X509Certificate.parse(chain.first).publicKey.base64);
      expect(status(r, AttestationCheckIds.keyDescription), CheckStatus.fail);
      expect(r.keyDescription, isNull);
      expect(r.passed, isFalse);
    });

    test('a non-DER deviceLocked boolean is flagged as a warning', () {
      final chain = certificatesFromPem(
          fixtureText('attestation/invalid/malformed_rot_device_locked.pem'));
      final leaf = X509Certificate.parse(chain.first);
      final kd = KeyDescription.fromCertificate(leaf)!;
      final r = AttestationVerifier(now: () => DateTime.utc(2022)).verify(
        chain: chain,
        expectedChallenge: kd.attestationChallenge,
        expectedPublicKey: leaf.publicKey.base64,
      );
      expect(status(r, AttestationCheckIds.keyDescriptionEncoding),
          CheckStatus.warn);
      expect(r.passed, isTrue, reason: r.failures.join('\n'));
    });

    test('ML-DSA key fails cleanly', () {
      final m = AttestationFixture('tokay/sdk37/TEE_MLDSA_RKP');
      final r = verifyFixture(m);
      expect(status(r, AttestationCheckIds.chainLinks), CheckStatus.pass);
      expect(status(r, AttestationCheckIds.publicKey), CheckStatus.fail);
      expect(r.check(AttestationCheckIds.publicKey)!.detail,
          contains('ML-DSA-65'));
      expect(r.passed, isFalse);
    });

    test('garbage never throws', () {
      final r = AttestationVerifier().verify(
        chain: [
          Uint8List.fromList([1, 2, 3])
        ],
        expectedChallenge: Uint8List(1),
        expectedPublicKey: '',
      );
      expect(r.passed, isFalse);
      expect(r.trustTier, TrustTier.untrusted);
    });
  });

  group('synthetic chains', () {
    final synthetic = SyntheticAttestation();
    final device = SoftwareEcKeyPair.generate();
    final challenge = Uint8List.fromList(List.generate(32, (i) => i));

    AttestationReport verify(List<Uint8List> chain,
            {String? publicKey, Uint8List? expectedChallenge}) =>
        AttestationVerifier(trustedRootSpkiSha256: {synthetic.rootSpkiSha256})
            .verify(
          chain: chain,
          expectedChallenge: expectedChallenge ?? challenge,
          expectedPublicKey: publicKey ?? device.publicKey.base64,
        );

    test('trusted only when the synthetic root is configured', () {
      final chain =
          synthetic.chainFor(attestedSpki: device.spki, challenge: challenge);
      expect(verify(chain).passed, isTrue);
      final untrusted = AttestationVerifier().verify(
        chain: chain,
        expectedChallenge: challenge,
        expectedPublicKey: device.publicKey.base64,
      );
      expect(untrusted.passed, isFalse);
      expect(
          SyntheticAttestation.defaultRootSpkiSha256, synthetic.rootSpkiSha256);
    });

    test('attestsBiometricOnly reflects userAuthType and noAuthRequired', () {
      AttestationReport withProps(SyntheticKeyProperties p) =>
          verify(synthetic.chainFor(
              attestedSpki: device.spki, challenge: challenge, properties: p));
      final biometric = withProps(const SyntheticKeyProperties());
      expect(biometric.passed, isTrue);
      expect(biometric.attestsBiometricOnly, isTrue);
      expect(biometric.check(AttestationCheckIds.userAuth)!.detail,
          contains('Biometric only'));
      final either = withProps(const SyntheticKeyProperties(userAuthType: 3));
      expect(either.attestsBiometricOnly, isFalse);
      expect(either.check(AttestationCheckIds.userAuth)!.detail,
          contains('Biometric or device credential'));
      final silent =
          withProps(const SyntheticKeyProperties(noAuthRequired: true));
      expect(silent.attestsBiometricOnly, isFalse);
      expect(silent.check(AttestationCheckIds.userAuth)!.detail,
          contains('noAuthRequired'));
    });

    test('software security level is rejected', () {
      final r = verify(synthetic.chainFor(
        attestedSpki: device.spki,
        challenge: challenge,
        properties:
            const SyntheticKeyProperties(securityLevel: SecurityLevel.software),
      ));
      expect(status(r, AttestationCheckIds.securityLevel), CheckStatus.fail);
    });

    test('imported keys are rejected', () {
      final r = verify(synthetic.chainFor(
        attestedSpki: device.spki,
        challenge: challenge,
        properties: const SyntheticKeyProperties(origin: KeyOrigin.imported),
      ));
      expect(status(r, AttestationCheckIds.origin), CheckStatus.fail);
    });

    test(
        'selection walks from the root: an appended fake certificate is '
        'ignored and rejected', () {
      final genuine =
          synthetic.chainFor(attestedSpki: device.spki, challenge: challenge);
      // Whoever holds the attested key can sign a certificate below it,
      // with a fake extension carrying their own challenge and key.
      final attacker = SoftwareEcKeyPair.generate();
      final fakeChallenge = utf8.encode('attacker challenge');
      final fake = buildCertificate(
        subject: const [DnAttribute('2.5.4.3', 'Fake')],
        issuer: const [DnAttribute('2.5.4.3', 'Android Keystore Key')],
        subjectPublicKeySpki: attacker.spki,
        signer: CertificateSigner.ec(device),
        extensions: {
          X509Oids.keyAttestation: encodeKeyDescription(
            challenge: fakeChallenge,
            hardwareEnforced: [
              authorizationEntry(
                  KeyMintTag.algorithm, DerEncoder.integerInt(3)),
            ],
          ),
        },
      );
      final extended = [fake, ...genuine];
      // The link fake → leaf verifies: the device key really signed it.
      final r = verify(
        extended,
        publicKey: attacker.publicKey.base64,
        expectedChallenge: Uint8List.fromList(fakeChallenge),
      );
      expect(status(r, AttestationCheckIds.chainLinks), CheckStatus.pass);
      expect(r.selectedCertificateIndex, 1);
      expect(
          status(r, AttestationCheckIds.extensionPosition), CheckStatus.fail);
      // The genuine extension is used, so the attacker's claims fail.
      expect(status(r, AttestationCheckIds.challenge), CheckStatus.fail);
      expect(status(r, AttestationCheckIds.publicKey), CheckStatus.fail);
      expect(r.passed, isFalse);
    });

    test('no extension anywhere', () {
      final rootKey = SoftwareEcKeyPair.generate();
      const name = [DnAttribute('2.5.4.3', 'Root')];
      final root = buildCertificate(
        subject: name,
        issuer: name,
        subjectPublicKeySpki: rootKey.spki,
        signer: CertificateSigner.ec(rootKey),
        isCa: true,
      );
      final leaf = buildCertificate(
        subject: const [DnAttribute('2.5.4.3', 'Leaf')],
        issuer: name,
        subjectPublicKeySpki: device.spki,
        signer: CertificateSigner.ec(rootKey),
      );
      final r = AttestationVerifier(
              trustedRootSpkiSha256: {toHex(rootKey.publicKey.spkiSha256)})
          .verify(
              chain: [leaf, root],
              expectedChallenge: challenge,
              expectedPublicKey: device.publicKey.base64);
      expect(status(r, AttestationCheckIds.extensionPresent), CheckStatus.fail);
      expect(r.keyDescription, isNull);
    });
  });

  group('report', () {
    test('JSON round trip', () {
      final f = AttestationFixture('caiman/sdk36/SB_EC_RKP');
      final r = verifyFixture(f);
      final restored = AttestationReport.fromJson(
          jsonDecode(jsonEncode(r.toJson())) as Map<String, dynamic>);
      expect(restored.passed, r.passed);
      expect(restored.trustTier, r.trustTier);
      expect(restored.checks.map((c) => c.toJson()),
          r.checks.map((c) => c.toJson()));
      expect(restored.keyDescription!.toJson(), r.keyDescription!.toJson());
      expect(restored.certificates.map((c) => c.toJson()),
          r.certificates.map((c) => c.toJson()));
      expect(restored.chain, f.chain);
      expect(restored.verifiedAt, r.verifiedAt);
      expect(restored.chainPem, contains('BEGIN CERTIFICATE'));
    });

    test('notProvided has tier none and does not pass', () {
      final r = AttestationReport.notProvided('iOS has no key attestation');
      expect(r.trustTier, TrustTier.none);
      expect(r.passed, isFalse);
      expect(r.failures, isEmpty);
      expect(AttestationReport.fromJson(r.toJson()).checks.single.detail,
          'iOS has no key attestation');
    });

    test('policy JSON round trip', () {
      const policy = AttestationPolicy(
        expectedPackageName: 'com.example',
        expectedSigningCertificateDigests: {'ab'},
        requireLockedBootloader: true,
        allowedSecurityLevels: {SecurityLevel.strongBox},
      );
      final restored = AttestationPolicy.fromJson(
          jsonDecode(jsonEncode(policy.toJson())) as Map<String, dynamic>);
      expect(restored.toJson(), policy.toJson());
      expect(
          const AttestationPolicy()
              .copyWith(requireLockedBootloader: true)
              .requireLockedBootloader,
          isTrue);
    });
  });
}

int _indexOf(List<int> haystack, List<int> needle) {
  outer:
  for (var i = 0; i <= haystack.length - needle.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}
