import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fixtures.dart';

void main() {
  group('Apple variant', () {
    final v = fixtureJson('vectors/apple_vectors.json')['ecies']
        as Map<String, dynamic>;
    // SecKeyCopyExternalRepresentation: 04 || X || Y || D.
    final x963 = fromHex(v['privateKeyX963'] as String);
    final d = bytesToBigInt(x963.sublist(65));
    final publicPoint = x963.sublist(0, 65);

    test('decrypts a SecKeyCreateEncryptedData payload', () {
      final plain =
          eciesReferenceDecrypt(d, b64(v['payload']), EciesVariant.apple);
      expect(utf8.decode(plain), v['plaintext']);
    });

    test('the exported private key matches the public key', () {
      final pair = SoftwareEcKeyPair.fromPrivateScalar(EcCurve.p256, d);
      expect(pair.publicKey.uncompressedPoint, publicPoint);
      expect(pair.toX963PrivateRepresentation(), x963);
    });

    test('the Android variant cannot decrypt an Apple payload', () {
      expect(
        () => eciesReferenceDecrypt(d, b64(v['payload']), EciesVariant.android),
        throwsA(isA<AesGcmAuthenticationException>()),
      );
    });

    test('round-trips', () {
      final spki = encodeEcSpki(EcCurve.p256, publicPoint);
      final payload =
          eciesEncrypt(spki, utf8.encode('round trip'), EciesVariant.apple);
      expect(payload.length, 65 + 10 + 16);
      expect(payload[0], 0x04);
      expect(utf8.decode(eciesReferenceDecrypt(d, payload, EciesVariant.apple)),
          'round trip');
    });
  });

  group('Android variant', () {
    final v = fixtureJson('vectors/android_vectors.json')['ecies']
        as Map<String, dynamic>;
    final d = BigInt.parse(v['privateScalarHex'] as String, radix: 16);

    test('decrypts a payload from the JCA port of the plugin code', () {
      final plain =
          eciesReferenceDecrypt(d, b64(v['payload']), EciesVariant.android);
      expect(utf8.decode(plain), v['plaintext']);
    });

    test('the Apple variant cannot decrypt an Android payload', () {
      expect(
        () => eciesReferenceDecrypt(d, b64(v['payload']), EciesVariant.apple),
        throwsA(isA<AesGcmAuthenticationException>()),
      );
    });

    test('round-trips against the recorded public key', () {
      final spki = b64(v['publicKeySpki']);
      final payload =
          eciesEncrypt(spki, utf8.encode('hybrid mode'), EciesVariant.android);
      expect(
          utf8.decode(eciesReferenceDecrypt(d, payload, EciesVariant.android)),
          'hybrid mode');
    });
  });

  group('input validation', () {
    final pair = SoftwareEcKeyPair.generate();

    test('rejects short payloads and compressed ephemeral keys', () {
      expect(
        () => eciesReferenceDecrypt(pair.d, Uint8List(80), EciesVariant.apple),
        throwsFormatException,
      );
      final payload =
          eciesEncrypt(pair.spki, utf8.encode('x'), EciesVariant.apple);
      payload[0] = 0x02;
      expect(
        () => eciesReferenceDecrypt(pair.d, payload, EciesVariant.apple),
        throwsFormatException,
      );
    });

    test('rejects an ephemeral point that is not on the curve', () {
      final payload =
          eciesEncrypt(pair.spki, utf8.encode('x'), EciesVariant.apple);
      payload[64] ^= 0x01; // corrupt Y
      expect(
        () => eciesReferenceDecrypt(pair.d, payload, EciesVariant.apple),
        throwsFormatException,
      );
    });

    test('rejects a tampered ciphertext', () {
      final payload =
          eciesEncrypt(pair.spki, utf8.encode('secret'), EciesVariant.android);
      payload[payload.length - 1] ^= 0x01;
      expect(
        () => eciesReferenceDecrypt(pair.d, payload, EciesVariant.android),
        throwsA(isA<AesGcmAuthenticationException>()),
      );
    });

    test('refuses non-P-256 recipients', () {
      final p384 = SoftwareEcKeyPair.generate(curve: EcCurve.p384);
      expect(
        () => eciesEncrypt(p384.spki, Uint8List(1), EciesVariant.apple),
        throwsArgumentError,
      );
    });
  });

  test('X9.63 KDF concatenates SHA-256(Z || counter || sharedInfo)', () {
    final z = Uint8List.fromList(List.generate(32, (i) => i));
    final info = utf8.encode('info');
    final out = x963Kdf(z, 40, sharedInfo: info);
    final block1 = sha256Bytes([...z, 0, 0, 0, 1, ...info]);
    final block2 = sha256Bytes([...z, 0, 0, 0, 2, ...info]);
    expect(out, [...block1, ...block2.sublist(0, 8)]);
  });
}
