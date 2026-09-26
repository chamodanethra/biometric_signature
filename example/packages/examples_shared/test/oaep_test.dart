import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fixtures.dart';

void main() {
  final openssl = fixtureJson('vectors/openssl_vectors.json');
  final opensslOaep = openssl['oaep'] as Map<String, dynamic>;
  final opensslKey = SoftwareRsaKeyPair.fromPkcs8Der(b64(((openssl['keys']
      as Map<String, dynamic>)['rsa2048'] as Map<String, dynamic>)['pkcs8']));

  group('decrypts third-party ciphertexts', () {
    test('openssl SHA-256 / MGF1-SHA-1 (Android parameters)', () {
      final plain = rsaOaepDecrypt(
        key: opensslKey,
        ciphertext: b64(opensslOaep['mgf1_sha1']),
        params: RsaOaepParameters.android,
      );
      expect(utf8.decode(plain), opensslOaep['plaintext']);
    });

    test('openssl SHA-256 / MGF1-SHA-256 (Apple parameters)', () {
      final plain = rsaOaepDecrypt(
        key: opensslKey,
        ciphertext: b64(opensslOaep['mgf1_sha256']),
        params: RsaOaepParameters.apple,
      );
      expect(utf8.decode(plain), opensslOaep['plaintext']);
    });

    test('the wrong MGF1 digest fails to decrypt', () {
      expect(
        () => rsaOaepDecrypt(
          key: opensslKey,
          ciphertext: b64(opensslOaep['mgf1_sha1']),
          params: RsaOaepParameters.apple,
        ),
        throwsA(isA<OaepDecryptionException>()),
      );
      expect(
        () => rsaOaepDecrypt(
          key: opensslKey,
          ciphertext: b64(opensslOaep['mgf1_sha256']),
          params: RsaOaepParameters.android,
        ),
        throwsA(isA<OaepDecryptionException>()),
      );
    });

    test('JCA vector (the Android keystore cipher configuration)', () {
      final v = fixtureJson('vectors/android_vectors.json')['rsaOaep']
          as Map<String, dynamic>;
      final key = SoftwareRsaKeyPair.fromPkcs8Der(b64(v['privateKeyPkcs8']));
      final plain = rsaOaepDecrypt(
        key: key,
        ciphertext: b64(v['payload']),
        params: RsaOaepParameters.android,
      );
      expect(utf8.decode(plain), v['plaintext']);
    });

    test('Apple Security framework vector (rsaEncryptionOAEPSHA256)', () {
      final v = fixtureJson('vectors/apple_vectors.json')['rsaOaep']
          as Map<String, dynamic>;
      final key = SoftwareRsaKeyPair.fromPkcs1Der(b64(v['privateKeyPkcs1']));
      final plain = rsaOaepDecrypt(
        key: key,
        ciphertext: b64(v['payload']),
        params: RsaOaepParameters.apple,
      );
      expect(utf8.decode(plain), v['plaintext']);
    });
  });

  group('encrypt', () {
    test('round-trips with both parameter sets', () {
      for (final params in [
        RsaOaepParameters.android,
        RsaOaepParameters.apple
      ]) {
        final message = utf8.encode('hello ${params.mgf1Hash.label}');
        final ct = rsaOaepEncrypt(
            key: opensslKey.publicKey, message: message, params: params);
        expect(ct.length, 256);
        expect(
          rsaOaepDecrypt(key: opensslKey, ciphertext: ct, params: params),
          message,
        );
      }
    });

    test('allows exactly 190 bytes for RSA-2048 and rejects 191', () {
      expect(RsaOaepParameters.android.maxMessageLength(256), 190);
      final max = Uint8List(190)..fillRange(0, 190, 0x41);
      final ct = rsaOaepEncrypt(
          key: opensslKey.publicKey,
          message: max,
          params: RsaOaepParameters.android);
      expect(
        rsaOaepDecrypt(
            key: opensslKey, ciphertext: ct, params: RsaOaepParameters.android),
        max,
      );
      expect(
        () => rsaOaepEncrypt(
            key: opensslKey.publicKey,
            message: Uint8List(191),
            params: RsaOaepParameters.android),
        throwsArgumentError,
      );
    });

    test('ciphertexts are randomized', () {
      final a = rsaOaepEncrypt(
          key: opensslKey.publicKey,
          message: [1, 2, 3],
          params: RsaOaepParameters.apple);
      final b = rsaOaepEncrypt(
          key: opensslKey.publicKey,
          message: [1, 2, 3],
          params: RsaOaepParameters.apple);
      expect(a, isNot(equals(b)));
    });

    test('tampered ciphertext fails', () {
      final ct = rsaOaepEncrypt(
          key: opensslKey.publicKey,
          message: [1, 2, 3],
          params: RsaOaepParameters.apple);
      ct[100] ^= 0x01;
      expect(
        () => rsaOaepDecrypt(
            key: opensslKey, ciphertext: ct, params: RsaOaepParameters.apple),
        throwsA(isA<OaepDecryptionException>()),
      );
    });
  });

  test('MGF1 matches RFC 8017 construction', () {
    // MGF1-SHA-1("foo", 3) = 1ac907 (well-known value).
    expect(toHex(mgf1(utf8.encode('foo'), 3, HashAlgorithm.sha1)), '1ac907');
    expect(
        toHex(mgf1(utf8.encode('foo'), 5, HashAlgorithm.sha1)), '1ac9075cd4');
  });
}
