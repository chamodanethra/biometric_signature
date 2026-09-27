import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart' show SecureRandom;

import '../encoding/bytes.dart';
import 'aes_gcm.dart';
import 'encryption_target.dart';

/// Envelope encryption for data too large for RSA-OAEP, or binary data.
///
/// The content is encrypted with a random AES-256-GCM data key. The data key
/// is base64-encoded (because the plugin's `decrypt()` returns UTF-8 text)
/// and encrypted with the device's [EncryptionScheme]. To open it:
/// 1. `decrypt(payload: envelope.wrappedKeyBase64, payloadFormat: base64)`
///    on the device (this prompts);
/// 2. [openEnvelope] with the returned `decryptedData`.
///
/// Note that step 2 puts the data key in Dart memory for a moment.
class SealedEnvelope {
  /// Creates an envelope from its parts.
  const SealedEnvelope({
    required this.wrappedKey,
    required this.iv,
    required this.ciphertext,
    required this.schemeLabel,
  });

  /// Restores an envelope from [toJson].
  factory SealedEnvelope.fromJson(Map<String, dynamic> json) {
    final version = json['v'];
    if (version != 1) {
      throw FormatException('Unsupported envelope version $version');
    }
    return SealedEnvelope(
      wrappedKey: base64.decode(json['wrappedKey'] as String),
      iv: base64.decode(json['iv'] as String),
      ciphertext: base64.decode(json['ciphertext'] as String),
      schemeLabel: json['scheme'] as String? ?? '',
    );
  }

  /// The base64 data key, encrypted to the device key.
  final Uint8List wrappedKey;

  /// The 12-byte AES-GCM IV of the content.
  final Uint8List iv;

  /// AES-256-GCM `ciphertext || tag` of the content.
  final Uint8List ciphertext;

  /// Which device scheme wrapped the key (informational).
  final String schemeLabel;

  /// [wrappedKey] as base64, the payload to pass to `decrypt()`.
  String get wrappedKeyBase64 => base64.encode(wrappedKey);

  /// JSON-safe map (all bytes as base64).
  Map<String, dynamic> toJson() => {
        'v': 1,
        'alg': 'A256GCM',
        'scheme': schemeLabel,
        'wrappedKey': base64.encode(wrappedKey),
        'iv': base64.encode(iv),
        'ciphertext': base64.encode(ciphertext),
      };
}

/// Encrypts [plaintext] under a fresh AES-256 data key and wraps the key
/// (as base64 text) with [scheme].
///
/// Throws [UnsupportedError] if [scheme] cannot encrypt.
SealedEnvelope sealEnvelope(
  EncryptionScheme scheme,
  Uint8List plaintext, {
  SecureRandom? random,
}) {
  final dataKey = random?.nextBytes(32) ?? secureRandomBytes(32);
  final iv = random?.nextBytes(12) ?? secureRandomBytes(12);
  final ciphertext = aesGcmEncrypt(key: dataKey, iv: iv, plaintext: plaintext);
  final wrappedKey = scheme.encrypt(base64.encode(dataKey), random: random);
  return SealedEnvelope(
    wrappedKey: wrappedKey,
    iv: iv,
    ciphertext: ciphertext,
    schemeLabel: scheme.label,
  );
}

/// Opens [envelope] with the data key the device returned from `decrypt()`
/// (the base64 text that was wrapped).
///
/// Throws [FormatException] if [dataKeyBase64] is not a 32-byte base64 key
/// and [AesGcmAuthenticationException] if the content was tampered with.
Uint8List openEnvelope(String dataKeyBase64, SealedEnvelope envelope) {
  final Uint8List dataKey;
  try {
    dataKey = base64.decode(dataKeyBase64.trim());
  } on FormatException {
    throw const FormatException('Decrypted data key is not base64');
  }
  if (dataKey.length != 32) {
    throw FormatException(
        'Decrypted data key must be 32 bytes, got ${dataKey.length}');
  }
  return aesGcmDecrypt(
    key: dataKey,
    iv: envelope.iv,
    ciphertextWithTag: envelope.ciphertext,
  );
}
