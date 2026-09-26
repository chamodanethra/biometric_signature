import 'dart:typed_data';

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/testing.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/attestation_fixtures.dart';

void main() {
  AttestationCheck check(ChainValidationResult r, String id) =>
      r.checks.firstWhere((c) => c.id == id);

  test('RKP chain (RSA root, P-384 + P-256 intermediates) validates', () {
    final f = AttestationFixture('caiman/sdk36/TEE_EC_RKP');
    final r = ChainValidator(now: () => f.validAt).validate(f.chain);
    expect(r.isValid, isTrue, reason: '${r.checks}');
    expect(r.rootKind, ChainRootKind.trusted);
    expect(r.provisioningMethod, ProvisioningMethod.remotelyProvisioned);
    expect(r.rootSpkiSha256, googleAttestationRoots.first.spkiSha256);
  });

  test('2025 ECDSA P-384 root validates (frankel, tegu)', () {
    for (final path in [
      'frankel/sdk37/TEE_EC_2026',
      'tegu/sdk36/SB_EC_2026_ROOT',
    ]) {
      final f = AttestationFixture(path);
      final r = ChainValidator(now: () => f.validAt).validate(f.chain);
      expect(r.isValid, isTrue, reason: path);
      expect(check(r, AttestationCheckIds.chainRoot).detail, contains('P-384'));
    }
  });

  test('P-256 issuer signing with ecdsa-with-SHA384 validates', () {
    final certs = AttestationFixture('p256_sha384_intermediate').chain;
    final root = X509Certificate.parse(certs.last);
    final r = ChainValidator(
      trustedRootSpkiSha256: {toHex(root.spkiSha256)},
      now: () => DateTime.utc(2025),
    ).validate(certs);
    expect(r.isValid, isTrue, reason: '${r.checks}');
    expect(check(r, AttestationCheckIds.chainLinks).detail,
        contains('SHA384withECDSA'));
  });

  group('validity', () {
    test('expired RKP intermediate fails', () {
      final f = AttestationFixture('caiman/sdk36/TEE_EC_RKP');
      final r =
          ChainValidator(now: () => DateTime.utc(2026, 6)).validate(f.chain);
      expect(
          check(r, AttestationCheckIds.chainValidity).status, CheckStatus.fail);
      expect(r.isValid, isFalse);
    });

    test('expired factory-provisioned intermediate only warns', () {
      final f = AttestationFixture('walleye/sdk27/TEE_EC_NONE');
      final r = ChainValidator(now: () => DateTime.utc(2027)).validate(f.chain);
      expect(r.provisioningMethod, ProvisioningMethod.factoryProvisioned);
      expect(
          check(r, AttestationCheckIds.chainValidity).status, CheckStatus.warn);
      expect(r.isValid, isTrue);
    });

    test('not-yet-valid intermediate fails', () {
      final f = AttestationFixture('caiman/sdk36/TEE_EC_RKP');
      final r = ChainValidator(now: () => DateTime.utc(2020)).validate(f.chain);
      expect(check(r, AttestationCheckIds.chainValidity).detail,
          contains('not valid until'));
    });

    test('the leaf validity is ignored', () {
      // The synthetic leaf is valid 1970–2048; check at 2060 with
      // long-lived intermediates.
      final synthetic = SyntheticAttestation();
      final chain = synthetic.chainFor(
        attestedSpki: SoftwareEcKeyPair.generate().spki,
        challenge: [1],
      );
      final r = ChainValidator(
        trustedRootSpkiSha256: {synthetic.rootSpkiSha256},
        now: () => DateTime.utc(2060),
      ).validate(chain);
      expect(r.isValid, isTrue);
    });
  });

  group('failures', () {
    final f = AttestationFixture('akita/sdk34/TEE_EC_NONE');

    test('a flipped signature byte breaks the link', () {
      final chain = [...f.chain];
      final tampered = Uint8List.fromList(chain[1]);
      tampered[tampered.length - 3] ^= 0x01;
      chain[1] = tampered;
      final r = ChainValidator(now: () => f.validAt).validate(chain);
      expect(check(r, AttestationCheckIds.chainLinks).status, CheckStatus.fail);
      expect(check(r, AttestationCheckIds.chainLinks).detail, contains('#1'));
    });

    test('an untrusted root key fails', () {
      final r = ChainValidator(trustedRootSpkiSha256: {}, now: () => f.validAt)
          .validate(f.chain);
      expect(r.rootKind, ChainRootKind.unknown);
      expect(check(r, AttestationCheckIds.chainRoot).detail,
          contains('Untrusted root'));
    });

    test('a chain without its root is incomplete', () {
      final r = ChainValidator(now: () => f.validAt)
          .validate(f.chain.sublist(0, f.chain.length - 1));
      expect(check(r, AttestationCheckIds.chainLinks).detail,
          contains('not self-issued'));
      expect(check(r, AttestationCheckIds.chainRoot).status, CheckStatus.fail);
    });

    test('reordered certificates break name chaining', () {
      final chain = [f.chain[0], f.chain[2], f.chain[1], ...f.chain.sublist(3)];
      final r = ChainValidator(now: () => f.validAt).validate(chain);
      expect(check(r, AttestationCheckIds.chainLinks).detail,
          contains('does not match'));
    });

    test('empty, single and garbage chains fail without throwing', () {
      final v = ChainValidator();
      expect(v.validate(const []).isValid, isFalse);
      expect(v.validate([f.chain.first]).isValid, isFalse);
      final r = v.validate([
        Uint8List.fromList([0x30, 0x03, 1, 2, 3]),
        f.chain.last
      ]);
      expect(check(r, AttestationCheckIds.chainParse).detail,
          contains('#0 could not be parsed'));
    });

    test('an unsupported link signature algorithm fails cleanly', () {
      final rootKey = SoftwareEcKeyPair.generate();
      const rootName = [DnAttribute('2.5.4.3', 'Root')];
      final root = buildCertificate(
        subject: rootName,
        issuer: rootName,
        subjectPublicKeySpki: rootKey.spki,
        signer: CertificateSigner.ec(rootKey),
        isCa: true,
      );
      final leaf = buildCertificate(
        subject: const [DnAttribute('2.5.4.3', 'Leaf')],
        issuer: rootName,
        subjectPublicKeySpki: SoftwareEcKeyPair.generate().spki,
        signer: CertificateSigner.ec(rootKey),
        signatureAlgorithmOverride: '2.16.840.1.101.3.4.3.18', // ML-DSA-65
      );
      final r = ChainValidator(
        trustedRootSpkiSha256: {toHex(rootKey.publicKey.spkiSha256)},
      ).validate([leaf, root]);
      final links = check(r, AttestationCheckIds.chainLinks);
      expect(links.status, CheckStatus.fail);
      expect(links.detail, contains('ML-DSA-65'));
    });
  });
}
