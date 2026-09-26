import 'dart:typed_data';

import 'package:pointycastle/api.dart' show SecureRandom;

import '../encoding/bytes.dart';
import 'aes_gcm.dart';
import 'hash.dart';
import 'public_key.dart';
import 'software_keys.dart';

/// The two ECIES flavours the plugin decrypts.
///
/// Both use the wire format
/// `ephemeral P-256 public key (65 bytes, 04||X||Y) || AES-GCM ciphertext || 16-byte tag`
/// and ANSI X9.63 KDF with SHA-256 over the ECDH x-coordinate Z, but they
/// derive the AES key and IV differently, so a payload for one platform does
/// not decrypt on the other.
enum EciesVariant {
  /// The plugin's Android hybrid mode (`CryptoOperations.kt`):
  /// `KDF(Z, sharedInfo = empty, 28 bytes)`; bytes 0–15 are the AES-128 key
  /// and bytes 16–27 the 12-byte GCM IV. No AAD.
  android,

  /// Apple `eciesEncryptionStandardX963SHA256AESGCM`:
  /// `KDF(Z, sharedInfo = ephemeral public key, 16 bytes)` is the AES-128
  /// key and the IV is 16 zero bytes. No AAD.
  apple;

  /// A one-line explanation of the exact parameters.
  String get description => switch (this) {
        EciesVariant.android =>
          'ECIES (Android): ECDH P-256, X9.63-KDF-SHA256 with empty shared '
              'info → 16-byte AES-128 key + 12-byte GCM IV, 128-bit tag',
        EciesVariant.apple =>
          'ECIES (Apple eciesEncryptionStandardX963SHA256AESGCM): ECDH '
              'P-256, X9.63-KDF-SHA256 with the ephemeral public key as '
              'shared info → AES-128 key, 16 zero-byte GCM IV, 128-bit tag',
      };
}

/// Length of the uncompressed ephemeral P-256 public key prefix.
const int eciesEphemeralKeyLength = 65;

/// Length of the GCM tag suffix.
const int eciesTagLength = 16;

/// ANSI X9.63 KDF with SHA-256: `SHA256(Z || counter_be32 || sharedInfo)`
/// for counter = 1, 2, … concatenated and truncated to [length].
Uint8List x963Kdf(List<int> z, int length, {List<int>? sharedInfo}) {
  final out = BytesBuilder(copy: false);
  var counter = 1;
  while (out.length < length) {
    final c = Uint8List(4)
      ..buffer.asByteData().setUint32(0, counter, Endian.big);
    out.add(HashAlgorithm.sha256
        .hash(concatBytes([z, c, sharedInfo ?? const <int>[]])));
    counter++;
  }
  return Uint8List.sublistView(out.toBytes(), 0, length);
}

({Uint8List key, Uint8List iv}) _deriveKeyAndIv(
  Uint8List z,
  Uint8List ephemeralPublicKey,
  EciesVariant variant,
) {
  switch (variant) {
    case EciesVariant.android:
      final derived = x963Kdf(z, 28);
      return (
        key: Uint8List.sublistView(derived, 0, 16),
        iv: Uint8List.sublistView(derived, 16, 28),
      );
    case EciesVariant.apple:
      return (
        key: x963Kdf(z, 16, sharedInfo: ephemeralPublicKey),
        iv: Uint8List(16),
      );
  }
}

/// Encrypts [plaintext] to a P-256 public key for the given [variant].
///
/// [recipientPublicKeySpki] is SubjectPublicKeyInfo DER (decode the plugin's
/// `publicKey` / `decryptingPublicKey` string with `publicKeyToSpki`).
/// Returns `ephemeralPublicKey(65) || ciphertext || tag(16)`; send it to the
/// device base64- or hex-encoded.
Uint8List eciesEncrypt(
  Uint8List recipientPublicKeySpki,
  Uint8List plaintext,
  EciesVariant variant, {
  SecureRandom? random,
}) {
  final recipient = ParsedPublicKey.fromSpki(recipientPublicKeySpki);
  if (recipient is! EcPublicKeyInfo || recipient.curve != EcCurve.p256) {
    throw ArgumentError.value(
      recipient.description,
      'recipientPublicKeySpki',
      'ECIES needs an EC P-256 public key',
    );
  }
  final ephemeral = SoftwareEcKeyPair.generate(random: random);
  final ephemeralPoint = ephemeral.publicKey.uncompressedPoint;
  final z = ephemeral.sharedSecret(recipient.point);
  final params = _deriveKeyAndIv(z, ephemeralPoint, variant);
  final sealed = aesGcmEncrypt(
    key: params.key,
    iv: params.iv,
    plaintext: plaintext,
  );
  return concatBytes([ephemeralPoint, sealed]);
}

/// Reference ECIES decryption for tests and the fake platform.
///
/// [privateScalar] is the recipient's P-256 private key d. Throws
/// [FormatException] for a malformed payload and
/// [AesGcmAuthenticationException] when the tag does not verify (for
/// example when the payload was made for the other [variant]).
Uint8List eciesReferenceDecrypt(
  BigInt privateScalar,
  Uint8List payload,
  EciesVariant variant,
) {
  if (payload.length < eciesEphemeralKeyLength + eciesTagLength) {
    throw FormatException('ECIES payload too short (${payload.length} bytes)');
  }
  final ephemeralBytes =
      Uint8List.sublistView(payload, 0, eciesEphemeralKeyLength);
  if (ephemeralBytes[0] != 0x04) {
    throw const FormatException(
        'ECIES ephemeral key must be uncompressed (0x04)');
  }
  final ephemeralPoint = decodeEcPoint(EcCurve.p256, ephemeralBytes);
  final recipient =
      SoftwareEcKeyPair.fromPrivateScalar(EcCurve.p256, privateScalar);
  final z = recipient.sharedSecret(ephemeralPoint);
  final params = _deriveKeyAndIv(z, ephemeralBytes, variant);
  return aesGcmDecrypt(
    key: params.key,
    iv: params.iv,
    ciphertextWithTag: Uint8List.sublistView(payload, eciesEphemeralKeyLength),
  );
}
