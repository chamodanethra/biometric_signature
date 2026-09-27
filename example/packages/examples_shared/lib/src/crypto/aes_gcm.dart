import 'dart:typed_data';

import 'package:pointycastle/api.dart' show AEADParameters, KeyParameter;
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/gcm.dart';

/// AES-GCM with a 128-bit tag. Returns `ciphertext || tag`.
///
/// [key] must be 16, 24 or 32 bytes. [iv] is normally 12 bytes; other
/// lengths are GHASHed as GCM specifies (Apple's ECIES uses 16 zero bytes).
Uint8List aesGcmEncrypt({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List plaintext,
  Uint8List? aad,
}) {
  final cipher = GCMBlockCipher(AESEngine())
    ..init(
        true, AEADParameters(KeyParameter(key), 128, iv, aad ?? Uint8List(0)));
  return cipher.process(plaintext);
}

/// Decrypts `ciphertext || tag` produced by [aesGcmEncrypt].
///
/// Throws [AesGcmAuthenticationException] if the tag does not verify.
Uint8List aesGcmDecrypt({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List ciphertextWithTag,
  Uint8List? aad,
}) {
  if (ciphertextWithTag.length < 16) {
    throw const AesGcmAuthenticationException('Ciphertext shorter than tag');
  }
  final cipher = GCMBlockCipher(AESEngine())
    ..init(
        false, AEADParameters(KeyParameter(key), 128, iv, aad ?? Uint8List(0)));
  try {
    return cipher.process(ciphertextWithTag);
  } catch (_) {
    throw const AesGcmAuthenticationException('AES-GCM tag mismatch');
  }
}

/// AES-GCM authentication failed (wrong key, IV, AAD or tampered data).
class AesGcmAuthenticationException implements Exception {
  /// Creates the exception.
  const AesGcmAuthenticationException(this.message);

  /// Description.
  final String message;

  @override
  String toString() => 'AesGcmAuthenticationException: $message';
}
