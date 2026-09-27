import 'dart:convert';

import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fixtures.dart';

void main() {
  final keys = fixtureJson('vectors/openssl_vectors.json')['keys']
      as Map<String, dynamic>;
  final rsa = (keys['rsa2048'] as Map<String, dynamic>)['spki'] as String;
  final ec = (keys['p256'] as Map<String, dynamic>)['spki'] as String;
  final ec2 = SoftwareEcKeyPair.generate().publicKey.base64;

  group('Android', () {
    test('hybrid mode → Android ECIES to decryptingPublicKey', () {
      final s = EncryptionTarget.resolve(
        platform: DevicePlatform.android,
        algorithm: 'EC',
        publicKey: ec,
        decryptingPublicKey: ec2,
        decryptingAlgorithm: 'EC',
        isHybridMode: true,
      );
      expect(s, isA<EciesScheme>());
      s as EciesScheme;
      expect(s.variant, EciesVariant.android);
      expect(s.publicKeySpki, base64.decode(ec2));
      expect(s.description, contains('empty shared info'));
    });

    test('RSA → OAEP SHA-256 / MGF1-SHA-1, needs enableDecryption', () {
      final s = EncryptionTarget.resolve(
          platform: DevicePlatform.android, algorithm: 'RSA', publicKey: rsa);
      expect(s, isA<RsaOaepScheme>());
      expect((s as RsaOaepScheme).mgf1, RsaOaepMgf1.sha1);
      expect(s.description, contains('enableDecryption'));
      expect(s.description, contains('MGF1 with SHA-1'));
    });

    test('EC signing-only key is unsupported', () {
      final s = EncryptionTarget.resolve(
          platform: DevicePlatform.android,
          algorithm: 'EC',
          publicKey: ec,
          isHybridMode: false);
      expect(s, isA<UnsupportedScheme>());
      expect(s.description, contains('enableDecryption'));
      expect(() => s.encrypt('x'), throwsUnsupportedError);
    });

    test('hybrid flag without the decrypting key is unsupported', () {
      final s = EncryptionTarget.resolve(
          platform: DevicePlatform.android,
          algorithm: 'EC',
          publicKey: ec,
          isHybridMode: true);
      expect(s, isA<UnsupportedScheme>());
    });
  });

  group('Apple', () {
    for (final platform in [DevicePlatform.ios, DevicePlatform.macos]) {
      test('${platform.label} EC → Apple ECIES to publicKey', () {
        final s = EncryptionTarget.resolve(
            platform: platform, algorithm: 'EC', publicKey: ec);
        expect((s as EciesScheme).variant, EciesVariant.apple);
        expect(s.publicKeySpki, base64.decode(ec));
      });

      test('${platform.label} RSA → OAEP MGF1-SHA-256 to publicKey', () {
        final s = EncryptionTarget.resolve(
            platform: platform, algorithm: 'RSA', publicKey: rsa);
        expect((s as RsaOaepScheme).mgf1, RsaOaepMgf1.sha256);
        expect(s.publicKeySpki, base64.decode(rsa));
      });
    }

    test('RSA prefers decryptingPublicKey when present (pre-13.1 iOS)', () {
      final s = EncryptionTarget.resolve(
        platform: DevicePlatform.ios,
        algorithm: 'RSA',
        publicKey: null,
        decryptingPublicKey: rsa,
        isHybridMode: true,
      );
      expect(s, isA<RsaOaepScheme>());
    });

    test('algorithm is inferred from the key when missing', () {
      expect(
          EncryptionTarget.resolve(platform: DevicePlatform.ios, publicKey: ec),
          isA<EciesScheme>());
      expect(
          EncryptionTarget.resolve(
              platform: DevicePlatform.macos,
              publicKey: spkiToPem(base64.decode(rsa))),
          isA<RsaOaepScheme>());
    });
  });

  test('Windows and other platforms are unsupported', () {
    for (final p in [DevicePlatform.windows, DevicePlatform.other]) {
      final s = EncryptionTarget.resolve(
          platform: p, algorithm: 'RSA', publicKey: rsa);
      expect(s.isSupported, isFalse);
    }
    expect(
        EncryptionTarget.resolve(
                platform: DevicePlatform.windows, publicKey: rsa)
            .description,
        contains('notAvailable'));
  });

  test('bad keys are unsupported, not exceptions', () {
    expect(
        EncryptionTarget.resolve(
            platform: DevicePlatform.ios, algorithm: 'EC', publicKey: 'zz!'),
        isA<UnsupportedScheme>());
    expect(
        EncryptionTarget.resolve(
            platform: DevicePlatform.ios, algorithm: 'EC', publicKey: rsa),
        isA<UnsupportedScheme>());
    expect(EncryptionTarget.resolve(platform: DevicePlatform.android),
        isA<UnsupportedScheme>());
  });

  test('schemes survive JSON', () {
    for (final s in <EncryptionScheme>[
      EciesScheme(EciesVariant.apple, base64.decode(ec)),
      RsaOaepScheme(RsaOaepMgf1.sha1, base64.decode(rsa)),
      const UnsupportedScheme('nope'),
    ]) {
      final restored = EncryptionScheme.fromJson(
          jsonDecode(jsonEncode(s.toJson())) as Map<String, dynamic>);
      expect(restored.toJson(), s.toJson());
      expect(restored.label, s.label);
    }
  });
}
