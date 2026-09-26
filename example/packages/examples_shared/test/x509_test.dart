import 'dart:math';
import 'dart:typed_data';

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/attestation_fixtures.dart';

void main() {
  final akita = AttestationFixture('akita/sdk34/TEE_EC_NONE');

  test('parses the fields of an attestation leaf', () {
    final leaf = X509Certificate.parse(akita.chain.first);
    expect(leaf.version, 3);
    expect(leaf.subject.commonName, 'Android Keystore Key');
    expect(leaf.issuer.organization, 'TEE');
    expect(leaf.serialNumber, BigInt.one);
    expect(leaf.notBefore, DateTime.utc(1970));
    expect(leaf.notAfter, DateTime.utc(2048));
    expect(leaf.signatureAlgorithm, SignatureAlgorithm.ecdsaSha256);
    expect(leaf.signatureAlgorithmName, 'SHA256withECDSA');
    expect(leaf.signatureAlgorithmsMatch, isTrue);
    expect(leaf.publicKey, isA<EcPublicKeyInfo>());
    expect(leaf.hasKeyAttestationExtension, isTrue);
    expect(leaf.extension(X509Oids.keyAttestation)!.critical, isFalse);
    expect(leaf.basicConstraints, isNull);
    expect(leaf.isSelfIssued, isFalse);
    expect(toHex(leaf.sha256Fingerprint), sha256Hex(akita.chain.first));
  });

  test('parses names that use serialNumber and title attributes', () {
    final certs =
        AttestationFixture('blueline/sdk28/SB_RSA_NONE_USERAUTH').certificates;
    expect(certs[1].subject.serialNumber, '90e8da3cadfc7820');
    expect(certs[1].subject.title, 'StrongBox');
    expect('${certs[1].subject}',
        'serialNumber=90e8da3cadfc7820, title=StrongBox');
    final root = certs.last;
    expect(root.isSelfIssued, isTrue);
    expect(root.basicConstraints!.isCa, isTrue);
    expect(root.publicKey.keySizeBits, 4096);
  });

  test('raw TBS bytes verify against the issuer key', () {
    final certs = akita.certificates;
    for (var i = 0; i < certs.length - 1; i++) {
      expect(certs[i].verifySignedBy(certs[i + 1].publicKey).isValid, isTrue,
          reason: 'link $i');
    }
    expect(certs.last.verifySignedBy(certs.last.publicKey).isValid, isTrue);
    expect(certs[0].verifySignedBy(certs[2].publicKey).isValid, isFalse);
  });

  test('name equivalence ignores case, spacing and string type', () {
    const a = DistinguishedName([
      DnAttribute('2.5.4.10', 'Google LLC'),
      DnAttribute('2.5.4.3', 'Droid  CA2'),
    ]);
    const b = DistinguishedName([
      DnAttribute('2.5.4.10', 'google llc'),
      DnAttribute('2.5.4.3', ' Droid CA2'),
    ]);
    const reordered = DistinguishedName([
      DnAttribute('2.5.4.3', 'Droid CA2'),
      DnAttribute('2.5.4.10', 'Google LLC'),
    ]);
    expect(a.equivalentTo(b), isTrue);
    expect(a.equivalentTo(reordered), isFalse);
    expect(a.equivalentTo(const DistinguishedName([])), isFalse);
  });

  test('toPem round-trips', () {
    final leaf = X509Certificate.parse(akita.chain.first);
    expect(certificatesFromPem(leaf.toPem()).single, akita.chain.first);
  });

  test('an ML-DSA key parses as unsupported instead of crashing', () {
    final leaf =
        AttestationFixture('tokay/sdk37/TEE_MLDSA_RKP').certificates.first;
    expect(leaf.publicKey, isA<UnsupportedPublicKey>());
    expect(leaf.publicKey.algorithm, 'ML-DSA-65');
    expect(leaf.publicKey.description, contains('unsupported'));
  });

  test('an unknown signature algorithm is reported, not thrown', () {
    final leaf = X509Certificate.parse(akita.chain.first);
    final issuer = X509Certificate.parse(akita.chain[1]);
    expect(leaf.verifySignedBy(issuer.publicKey), isA<VerifyValid>());
    expect(
        SignatureAlgorithm.nameForOid('2.16.840.1.101.3.4.3.18'), 'ML-DSA-65');
  });

  group('malformed input only ever throws CertificateParseException', () {
    final der = akita.chain[1];

    test('every truncation', () {
      for (var i = 0; i < der.length; i++) {
        expect(
          () => X509Certificate.parse(Uint8List.sublistView(der, 0, i)),
          throwsA(isA<CertificateParseException>()),
          reason: 'length $i',
        );
      }
    });

    test('random byte flips', () {
      final random = Random(42);
      for (var n = 0; n < 400; n++) {
        final copy = Uint8List.fromList(der);
        copy[random.nextInt(copy.length)] ^= 1 << random.nextInt(8);
        try {
          X509Certificate.parse(copy);
        } on CertificateParseException {
          // expected for most flips
        }
      }
    });

    test('garbage', () {
      expect(() => X509Certificate.parse(Uint8List.fromList([1, 2, 3])),
          throwsA(isA<CertificateParseException>()));
      expect(() => X509Certificate.parse(Uint8List(0)),
          throwsA(isA<CertificateParseException>()));
    });
  });
}
