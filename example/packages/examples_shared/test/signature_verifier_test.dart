import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fixtures.dart';

void main() {
  final v = fixtureJson('vectors/openssl_vectors.json');
  final keys = v['keys'] as Map<String, dynamic>;
  final sigs = v['signatures'] as Map<String, dynamic>;
  final message = b64(v['message']);
  String spki(String name) =>
      (keys[name] as Map<String, dynamic>)['spki'] as String;

  group('openssl vectors', () {
    test('RSA PKCS#1 v1.5 SHA-256 (plugin default) verifies', () {
      final outcome = verifySignature(
        publicKey: spki('rsa2048'),
        message: message,
        signature: b64(sigs['rsa_sha256']),
      );
      expect(outcome, isA<VerifyValid>());
      expect(outcome.isValid, isTrue);
    });

    test('RSA SHA-384 and SHA-512 verify with explicit algorithm', () {
      expect(
        verifySignature(
          publicKey: spki('rsa2048'),
          message: message,
          signature: b64(sigs['rsa_sha384']),
          algorithm: SignatureAlgorithm.rsaPkcs1Sha384,
        ).isValid,
        isTrue,
      );
      expect(
        verifySignature(
          publicKey: spki('rsa2048'),
          message: message,
          signature: b64(sigs['rsa_sha512']),
          algorithm: SignatureAlgorithm.rsaPkcs1Sha512,
        ).isValid,
        isTrue,
      );
    });

    test('RSA signature with the wrong hash is invalid', () {
      final outcome = verifySignature(
        publicKey: spki('rsa2048'),
        message: message,
        signature: b64(sigs['rsa_sha384']),
      );
      expect(outcome, isA<VerifyInvalid>());
    });

    test('ECDSA P-256 low-S and high-S both verify', () {
      final low = b64(sigs['p256_sha256_lowS']);
      final high = b64(sigs['p256_sha256_highS']);
      final curve = EcCurve.p256;
      expect(EcdsaSignatureValue.fromDer(low).isHighS(curve), isFalse);
      expect(EcdsaSignatureValue.fromDer(high).isHighS(curve), isTrue);
      for (final sig in [low, high]) {
        expect(
          verifySignature(
                  publicKey: spki('p256'), message: message, signature: sig)
              .isValid,
          isTrue,
        );
      }
      // Flipping S keeps a signature valid (malleability is expected).
      final flipped = EcdsaSignatureValue.fromDer(low).flipS(curve).toDer();
      expect(
        verifySignature(
                publicKey: spki('p256'), message: message, signature: flipped)
            .isValid,
        isTrue,
      );
    });

    test('ECDSA P-256 with SHA-384 (hash truncation) verifies', () {
      expect(
        verifySignature(
          publicKey: spki('p256'),
          message: message,
          signature: b64(sigs['p256_sha384']),
          algorithm: SignatureAlgorithm.ecdsaSha384,
        ).isValid,
        isTrue,
      );
    });

    test('ECDSA P-384 defaults to SHA-384', () {
      expect(
        verifySignature(
          publicKey: spki('p384'),
          message: message,
          signature: b64(sigs['p384_sha384']),
        ).isValid,
        isTrue,
      );
    });

    test('accepts PEM and hex encodings of the same key', () {
      final der = base64.decode(spki('p256'));
      for (final encoded in [spkiToPem(der), toHex(der), base64.encode(der)]) {
        expect(
          verifySignature(
            publicKey: encoded,
            message: message,
            signature: b64(sigs['p256_sha256_lowS']),
          ).isValid,
          isTrue,
        );
      }
    });
  });

  group('failures never throw', () {
    test('tampered message', () {
      final tampered = Uint8List.fromList(message)..[0] ^= 1;
      expect(
        verifySignature(
                publicKey: spki('p256'),
                message: tampered,
                signature: b64(sigs['p256_sha256_lowS']))
            .isValid,
        isFalse,
      );
      expect(
        verifySignature(
                publicKey: spki('rsa2048'),
                message: tampered,
                signature: b64(sigs['rsa_sha256']))
            .isValid,
        isFalse,
      );
    });

    test('garbage inputs return invalid outcomes', () {
      expect(
        verifySignature(
            publicKey: 'not a key', message: message, signature: [1]),
        isA<VerifyInvalid>(),
      );
      expect(
        verifySignature(
            publicKey: spki('p256'), message: message, signature: [1, 2]),
        isA<VerifyInvalid>(),
      );
      expect(
        verifySignature(
            publicKey: spki('rsa2048'), message: message, signature: [1, 2]),
        isA<VerifyInvalid>(),
      );
    });

    test('key/algorithm mismatch is invalid', () {
      final outcome = verifySignature(
        publicKey: spki('p256'),
        message: message,
        signature: b64(sigs['rsa_sha256']),
        algorithm: SignatureAlgorithm.rsaPkcs1Sha256,
      );
      expect(outcome, isA<VerifyInvalid>());
    });

    test('software key signatures round-trip', () {
      final ec = SoftwareEcKeyPair.generate();
      final sig = ec.sign(message);
      expect(
        verifySignature(
                publicKey: ec.publicKey.base64,
                message: message,
                signature: sig)
            .isValid,
        isTrue,
      );
      final rsa = SoftwareRsaKeyPair.fromPkcs8Der(
          b64((keys['rsa2048'] as Map<String, dynamic>)['pkcs8']));
      expect(
        verifySignature(
                publicKey: rsa.publicKey.toPem(),
                message: message,
                signature: rsa.sign(message))
            .isValid,
        isTrue,
      );
      // The software RSA signature is byte-identical to openssl's
      // (PKCS#1 v1.5 is deterministic).
      expect(rsa.sign(message), b64(sigs['rsa_sha256']));
    });
  });
}
