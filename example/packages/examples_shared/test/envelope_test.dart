import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fixtures.dart';

void main() {
  final device = SoftwareEcKeyPair.generate();
  final scheme = EciesScheme(EciesVariant.apple, device.spki);
  final content = Uint8List.fromList(List.generate(5000, (i) => i % 256));

  String deviceDecrypt(SealedEnvelope e) => utf8.decode(
      eciesReferenceDecrypt(device.d, e.wrappedKey, EciesVariant.apple));

  test('round trip: device unwraps the base64 data key, app opens content', () {
    final envelope = sealEnvelope(scheme, content);
    final dataKeyText = deviceDecrypt(envelope);
    expect(base64.decode(dataKeyText), hasLength(32));
    expect(openEnvelope(dataKeyText, envelope), content);
  });

  test('JSON round trip', () {
    final envelope = sealEnvelope(scheme, content);
    final json =
        jsonDecode(jsonEncode(envelope.toJson())) as Map<String, dynamic>;
    expect(json['alg'], 'A256GCM');
    final restored = SealedEnvelope.fromJson(json);
    expect(restored.schemeLabel, scheme.label);
    expect(openEnvelope(deviceDecrypt(restored), restored), content);
  });

  test('works with RSA-OAEP (the base64 data key fits in 190 bytes)', () {
    final keys = fixtureJson('vectors/openssl_vectors.json')['keys']
        as Map<String, dynamic>;
    final rsa = SoftwareRsaKeyPair.fromPkcs8Der(
        b64((keys['rsa2048'] as Map<String, dynamic>)['pkcs8']));
    final envelope =
        sealEnvelope(RsaOaepScheme(RsaOaepMgf1.sha1, rsa.spki), content);
    final dataKey = utf8.decode(rsaOaepDecrypt(
        key: rsa,
        ciphertext: envelope.wrappedKey,
        params: RsaOaepParameters.android));
    expect(openEnvelope(dataKey, envelope), content);
    expect(envelope.schemeLabel, 'RSA-OAEP (Android keystore)');
  });

  test('tampered content or wrong key fails', () {
    final envelope = sealEnvelope(scheme, content);
    final key = deviceDecrypt(envelope);
    final tampered = SealedEnvelope(
      wrappedKey: envelope.wrappedKey,
      iv: envelope.iv,
      ciphertext: Uint8List.fromList(envelope.ciphertext)..[0] ^= 1,
      schemeLabel: envelope.schemeLabel,
    );
    expect(() => openEnvelope(key, tampered),
        throwsA(isA<AesGcmAuthenticationException>()));
    expect(() => openEnvelope(base64.encode(Uint8List(32)), envelope),
        throwsA(isA<AesGcmAuthenticationException>()));
    expect(() => openEnvelope('not base64!', envelope), throwsFormatException);
    expect(() => openEnvelope(base64.encode(Uint8List(16)), envelope),
        throwsFormatException);
  });

  test('unsupported schemes refuse to seal', () {
    expect(() => sealEnvelope(const UnsupportedScheme('Windows'), content),
        throwsUnsupportedError);
  });
}
