// Encrypts a message with the Dart implementations against the keys in the
// recorded native vectors, and prints shell assignments. Feed them to the
// native tools to prove the Dart *encrypt* side matches the platforms:
//
//   dart run tool/cross_check_payloads.dart > /tmp/xcheck.env && . /tmp/xcheck.env
//   swift tool/gen_apple_vectors.swift decrypt-ecies "$APPLE_EC_X963" "$APPLE_ECIES"
//   swift tool/gen_apple_vectors.swift decrypt-oaep "$APPLE_RSA_PKCS1" "$APPLE_OAEP"
//   java tool/AndroidVectors.java decrypt-ecies "$ANDROID_EC_D" "$ANDROID_ECIES"
//   java tool/AndroidVectors.java decrypt-oaep "$ANDROID_RSA_PKCS8" "$ANDROID_OAEP"
//
// Each command should print the message.

import 'dart:convert';
import 'dart:io';

import 'package:examples_shared/crypto.dart';

Map<String, dynamic> _load(String name) =>
    jsonDecode(File('test/fixtures/vectors/$name').readAsStringSync())
        as Map<String, dynamic>;

void main() {
  final apple = _load('apple_vectors.json');
  final android = _load('android_vectors.json');
  final appleEc = apple['ecies'] as Map<String, dynamic>;
  final appleRsa = apple['rsaOaep'] as Map<String, dynamic>;
  final androidEc = android['ecies'] as Map<String, dynamic>;
  final androidRsa = android['rsaOaep'] as Map<String, dynamic>;

  final x963 = fromHex(appleEc['privateKeyX963'] as String);
  final appleEcSpki = encodeEcSpki(EcCurve.p256, x963.sublist(0, 65));
  final appleRsaKey = SoftwareRsaKeyPair.fromPkcs1Der(
      base64.decode(appleRsa['privateKeyPkcs1'] as String));
  const message = 'Dart -> native cross-check';

  final out = <String, String>{
    'APPLE_EC_X963': appleEc['privateKeyX963'] as String,
    'APPLE_ECIES':
        EciesScheme(EciesVariant.apple, appleEcSpki).encryptToBase64(message),
    'APPLE_RSA_PKCS1': appleRsa['privateKeyPkcs1'] as String,
    'APPLE_OAEP': RsaOaepScheme(RsaOaepMgf1.sha256, appleRsaKey.spki)
        .encryptToBase64(message),
    'ANDROID_EC_D': androidEc['privateScalarHex'] as String,
    'ANDROID_ECIES': EciesScheme(EciesVariant.android,
            base64.decode(androidEc['publicKeySpki'] as String))
        .encryptToBase64(message),
    'ANDROID_RSA_PKCS8': androidRsa['privateKeyPkcs8'] as String,
    'ANDROID_OAEP': RsaOaepScheme(RsaOaepMgf1.sha1,
            base64.decode(androidRsa['publicKeySpki'] as String))
        .encryptToBase64(message),
  };
  out.forEach((key, value) => stdout.writeln("$key='$value'"));
}
