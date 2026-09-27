import 'dart:typed_data';

import 'package:pointycastle/api.dart' show SecureRandom;

import '../encoding/bytes.dart';
import 'hash.dart';
import 'public_key.dart';
import 'software_keys.dart';

/// RSAES-OAEP (RFC 8017 §7.1) with independently chosen hash and MGF1
/// digests.
///
/// pointycastle's `OAEPEncoding` always uses the main hash for MGF1, but the
/// platforms differ:
/// - Android keystore: SHA-256 main digest, **SHA-1** MGF1 digest.
/// - Apple `rsaEncryptionOAEPSHA256`: SHA-256 for both.
///
/// A ciphertext made with the wrong MGF1 digest fails to decrypt on device.
class RsaOaepParameters {
  /// Creates parameters. [label] defaults to empty (what both platforms use).
  const RsaOaepParameters({
    this.hash = HashAlgorithm.sha256,
    required this.mgf1Hash,
    this.label,
  });

  /// Android keystore: SHA-256 / MGF1-SHA-1.
  static const RsaOaepParameters android =
      RsaOaepParameters(mgf1Hash: HashAlgorithm.sha1);

  /// Apple Security framework: SHA-256 / MGF1-SHA-256.
  static const RsaOaepParameters apple =
      RsaOaepParameters(mgf1Hash: HashAlgorithm.sha256);

  /// Main digest (hashes the label).
  final HashAlgorithm hash;

  /// Digest used inside MGF1.
  final HashAlgorithm mgf1Hash;

  /// Optional label; `null` means empty.
  final Uint8List? label;

  /// Human-readable summary.
  String get description =>
      'RSA-OAEP, ${hash.label} digest, MGF1 with ${mgf1Hash.label}, '
      '${label == null || label!.isEmpty ? 'empty label' : 'custom label'}';

  /// Largest plaintext for a modulus of [modulusBytes] bytes
  /// (`k - 2·hLen - 2`; 190 bytes for RSA-2048 with SHA-256).
  int maxMessageLength(int modulusBytes) =>
      modulusBytes - 2 * hash.lengthBytes - 2;
}

/// MGF1 mask generation (RFC 8017 §B.2.1).
Uint8List mgf1(List<int> seed, int length, HashAlgorithm hash) {
  final out = BytesBuilder(copy: false);
  var counter = 0;
  while (out.length < length) {
    final c = Uint8List(4)
      ..buffer.asByteData().setUint32(0, counter, Endian.big);
    out.add(hash.hash(concatBytes([seed, c])));
    counter++;
  }
  return Uint8List.sublistView(out.toBytes(), 0, length);
}

/// Encrypts [message] to [key] with RSAES-OAEP.
///
/// Throws [ArgumentError] when the message is longer than
/// [RsaOaepParameters.maxMessageLength] (190 bytes for RSA-2048/SHA-256).
Uint8List rsaOaepEncrypt({
  required RsaPublicKeyInfo key,
  required List<int> message,
  required RsaOaepParameters params,
  SecureRandom? random,
}) {
  final k = key.modulusBytes;
  final hLen = params.hash.lengthBytes;
  final maxLen = params.maxMessageLength(k);
  if (message.length > maxLen) {
    throw ArgumentError.value(
      message.length,
      'message',
      'RSA-OAEP with a ${key.keySizeBits}-bit key and ${params.hash.label} '
          'can encrypt at most $maxLen bytes',
    );
  }
  final lHash = params.hash.hash(params.label ?? const <int>[]);
  final ps = Uint8List(k - message.length - 2 * hLen - 2);
  final db = concatBytes([
    lHash,
    ps,
    const [0x01],
    message
  ]);
  final seed = random?.nextBytes(hLen) ?? secureRandomBytes(hLen);
  final dbMask = mgf1(seed, k - hLen - 1, params.mgf1Hash);
  final maskedDb = _xor(db, dbMask);
  final seedMask = mgf1(maskedDb, hLen, params.mgf1Hash);
  final maskedSeed = _xor(seed, seedMask);
  final em = concatBytes([
    const [0x00],
    maskedSeed,
    maskedDb
  ]);
  final c = bytesToBigInt(em).modPow(key.exponent, key.modulus);
  return bigIntToBytes(c, length: k);
}

/// Reference RSAES-OAEP decryption, for tests and the fake platform.
///
/// Throws [OaepDecryptionException] with a single generic message for any
/// failure, as RFC 8017 recommends.
Uint8List rsaOaepDecrypt({
  required SoftwareRsaKeyPair key,
  required List<int> ciphertext,
  required RsaOaepParameters params,
}) {
  final k = key.modulusBytes;
  final hLen = params.hash.lengthBytes;
  if (ciphertext.length != k || k < 2 * hLen + 2) {
    throw const OaepDecryptionException();
  }
  final c = bytesToBigInt(ciphertext);
  if (c >= key.modulus) throw const OaepDecryptionException();
  final em = bigIntToBytes(key.privateOp(c), length: k);
  final maskedSeed = Uint8List.sublistView(em, 1, 1 + hLen);
  final maskedDb = Uint8List.sublistView(em, 1 + hLen);
  final seed = _xor(maskedSeed, mgf1(maskedDb, hLen, params.mgf1Hash));
  final db = _xor(maskedDb, mgf1(seed, k - hLen - 1, params.mgf1Hash));
  final lHash = params.hash.hash(params.label ?? const <int>[]);

  var bad = em[0];
  bad |= constantTimeEquals(Uint8List.sublistView(db, 0, hLen), lHash) ? 0 : 1;
  // Find the 0x01 separator after the zero padding.
  var separator = -1;
  var lookingForSeparator = 1;
  for (var i = hLen; i < db.length; i++) {
    final isOne = db[i] == 0x01 ? 1 : 0;
    final isZero = db[i] == 0x00 ? 1 : 0;
    if (lookingForSeparator == 1 && isOne == 1) separator = i;
    if (lookingForSeparator == 1 && isOne == 0 && isZero == 0) bad |= 1;
    if (isOne == 1) lookingForSeparator = 0;
  }
  if (separator < 0) bad |= 1;
  if (bad != 0) throw const OaepDecryptionException();
  return Uint8List.fromList(db.sublist(separator + 1));
}

Uint8List _xor(List<int> a, List<int> b) {
  final out = Uint8List(a.length);
  for (var i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

/// OAEP decryption failed. Deliberately carries no detail.
class OaepDecryptionException implements Exception {
  /// Creates the exception.
  const OaepDecryptionException();

  @override
  String toString() => 'OaepDecryptionException: decryption error';
}
