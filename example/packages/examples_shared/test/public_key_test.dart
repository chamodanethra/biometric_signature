import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fixtures.dart';

void main() {
  final keys = fixtureJson('vectors/openssl_vectors.json')['keys']
      as Map<String, dynamic>;
  Uint8List spki(String name) =>
      b64((keys[name] as Map<String, dynamic>)['spki']);

  group('publicKeyToSpki normalizes every plugin format', () {
    final der = spki('p256');

    test('base64 (KeyFormat.base64 and KeyFormat.raw)', () {
      final b64String = base64.encode(der);
      expect(b64String.startsWith('M'), isTrue);
      expect(detectPublicKeyEncoding(b64String), PublicKeyEncoding.base64);
      expect(publicKeyToSpki(b64String), der);
    });

    test('PEM, including Android-style 64-column lines', () {
      final pem = spkiToPem(der);
      expect(pem, startsWith('-----BEGIN PUBLIC KEY-----\n'));
      expect(detectPublicKeyEncoding(pem), PublicKeyEncoding.pem);
      expect(publicKeyToSpki(pem), der);
      expect(publicKeyToSpki('  $pem\n'), der);
    });

    test('hex, either case', () {
      expect(detectPublicKeyEncoding(toHex(der)), PublicKeyEncoding.hex);
      expect(publicKeyToSpki(toHex(der)), der);
      expect(publicKeyToSpki(toHex(der).toUpperCase()), der);
    });

    test('rejects garbage', () {
      expect(() => publicKeyToSpki(''), throwsFormatException);
      expect(() => publicKeyToSpki('!!!'), throwsFormatException);
      expect(
          () => publicKeyToSpki('-----BEGIN CERTIFICATE-----\nAAAA\n'
              '-----END CERTIFICATE-----'),
          throwsFormatException);
    });
  });

  test('parses RSA and EC keys with fingerprints', () {
    final rsa = ParsedPublicKey.fromSpki(spki('rsa2048'));
    expect(rsa, isA<RsaPublicKeyInfo>());
    expect(rsa.description, 'RSA 2048');
    expect((rsa as RsaPublicKeyInfo).exponent, BigInt.from(65537));
    expect(rsa.fingerprint, sha256Hex(spki('rsa2048')));

    final p256 = ParsedPublicKey.fromSpki(spki('p256'));
    expect(p256.description, 'EC P-256');
    expect((p256 as EcPublicKeyInfo).uncompressedPoint.length, 65);

    final p384 = ParsedPublicKey.fromSpki(spki('p384'));
    expect(p384.description, 'EC P-384');
  });

  test('re-encoding yields identical SPKI DER', () {
    final p256 = ParsedPublicKey.fromSpki(spki('p256')) as EcPublicKeyInfo;
    expect(encodeEcSpki(EcCurve.p256, p256.uncompressedPoint), spki('p256'));
    final rsa = ParsedPublicKey.fromSpki(spki('rsa2048')) as RsaPublicKeyInfo;
    expect(encodeRsaSpki(rsa.modulus, rsa.exponent), spki('rsa2048'));
  });

  test('sameKeyAs compares key material', () {
    final a = ParsedPublicKey.fromSpki(spki('p256'));
    expect(a.sameKeyAs(ParsedPublicKey.parse(spkiToPem(spki('p256')))), isTrue);
    expect(a.sameKeyAs(ParsedPublicKey.fromSpki(spki('p384'))), isFalse);
    expect(a.sameKeyAs(ParsedPublicKey.fromSpki(spki('rsa2048'))), isFalse);
  });

  test('rejects an EC point that is not on the curve', () {
    final p256 = ParsedPublicKey.fromSpki(spki('p256')) as EcPublicKeyInfo;
    final point = Uint8List.fromList(p256.uncompressedPoint);
    point[64] ^= 1;
    expect(() => ParsedPublicKey.fromSpki(encodeEcSpki(EcCurve.p256, point)),
        throwsFormatException);
  });

  test('unknown algorithms become UnsupportedPublicKey', () {
    final ed25519 = DerEncoder.sequence([
      DerEncoder.sequence([DerEncoder.oid('1.3.101.112')]),
      DerEncoder.bitString(Uint8List(32)),
    ]);
    final key = ParsedPublicKey.fromSpki(ed25519);
    expect(key, isA<UnsupportedPublicKey>());
    expect(key.algorithm, 'Ed25519');
  });

  test('malformed SPKI throws FormatException, never other errors', () {
    final der = spki('rsa2048');
    for (var i = 0; i < der.length; i += 7) {
      expect(() => ParsedPublicKey.fromSpki(Uint8List.sublistView(der, 0, i)),
          throwsFormatException);
    }
  });
}
