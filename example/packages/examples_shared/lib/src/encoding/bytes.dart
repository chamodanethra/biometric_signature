import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart' show KeyParameter, SecureRandom;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/random/fortuna_random.dart';

/// Returns [length] bytes from the platform's cryptographically secure RNG.
Uint8List secureRandomBytes(int length) {
  final random = Random.secure();
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = random.nextInt(256);
  }
  return out;
}

/// Creates a pointycastle [SecureRandom] seeded from [Random.secure].
///
/// Pass [seed] (32 bytes) only in tests that need deterministic output.
SecureRandom createSecureRandom({Uint8List? seed}) {
  final random = FortunaRandom();
  random.seed(KeyParameter(seed ?? secureRandomBytes(32)));
  return random;
}

/// Lower-case hex encoding of [bytes].
String toHex(List<int> bytes) {
  final buffer = StringBuffer();
  for (final b in bytes) {
    buffer.write((b & 0xff).toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

/// Decodes a hex string. Whitespace and `:` separators are ignored.
///
/// Throws [FormatException] for odd lengths or non-hex characters.
Uint8List fromHex(String hex) {
  final clean = hex.replaceAll(RegExp(r'[\s:]'), '');
  if (clean.length.isOdd) {
    throw const FormatException('Hex string has an odd number of digits');
  }
  if (!isHexString(clean)) {
    throw const FormatException('Hex string contains non-hex characters');
  }
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

final RegExp _hexPattern = RegExp(r'^[0-9a-fA-F]*$');

/// Whether [value] consists only of hex digits (an empty string counts).
bool isHexString(String value) => _hexPattern.hasMatch(value);

/// Decodes standard or URL-safe base64, with or without padding, ignoring
/// whitespace. Throws [FormatException] on invalid input.
Uint8List decodeBase64Lenient(String value) {
  var clean = value.replaceAll(RegExp(r'\s'), '');
  clean = clean.replaceAll('-', '+').replaceAll('_', '/');
  final remainder = clean.length % 4;
  if (remainder == 1) {
    throw const FormatException('Invalid base64 length');
  }
  if (remainder != 0) {
    clean = clean.padRight(clean.length + (4 - remainder), '=');
  }
  return base64.decode(clean);
}

/// Decodes a byte string that is either hex or base64.
///
/// A string made only of hex digits with an even length is treated as hex;
/// everything else as base64. This matches the plugin's `hex` / `base64`
/// output formats, but it is a heuristic: prefer to know the format.
Uint8List decodeBase64OrHex(String value) {
  final trimmed = value.trim();
  if (trimmed.isNotEmpty && trimmed.length.isEven && isHexString(trimmed)) {
    return fromHex(trimmed);
  }
  return decodeBase64Lenient(trimmed);
}

/// Compares two byte lists in time that depends only on their lengths.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= (a[i] ^ b[i]) & 0xff;
  }
  return diff == 0;
}

/// SHA-1 of [data]. Only used for OAEP's MGF1 on Android; never for signatures.
Uint8List sha1Bytes(List<int> data) =>
    SHA1Digest().process(Uint8List.fromList(data));

/// SHA-256 of [data].
Uint8List sha256Bytes(List<int> data) =>
    SHA256Digest().process(Uint8List.fromList(data));

/// SHA-384 of [data].
Uint8List sha384Bytes(List<int> data) =>
    SHA384Digest().process(Uint8List.fromList(data));

/// SHA-512 of [data].
Uint8List sha512Bytes(List<int> data) =>
    SHA512Digest().process(Uint8List.fromList(data));

/// SHA-256 of [data] as lower-case hex.
String sha256Hex(List<int> data) => toHex(sha256Bytes(data));

/// SHA-256 of the UTF-8 encoding of [text].
Uint8List sha256OfString(String text) => sha256Bytes(utf8.encode(text));

/// Concatenates byte lists.
Uint8List concatBytes(List<List<int>> parts) {
  final builder = BytesBuilder(copy: false);
  for (final part in parts) {
    builder.add(part);
  }
  return builder.toBytes();
}

/// Interprets [bytes] as an unsigned big-endian integer.
BigInt bytesToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b & 0xff);
  }
  return result;
}

/// Encodes a non-negative [value] as unsigned big-endian bytes.
///
/// With [length], the output is left-padded with zeros to exactly that many
/// bytes; an [ArgumentError] is thrown if the value does not fit.
Uint8List bigIntToBytes(BigInt value, {int? length}) {
  if (value.isNegative) {
    throw ArgumentError.value(value, 'value', 'must be non-negative');
  }
  final byteCount = (value.bitLength + 7) ~/ 8;
  final size = length ?? (byteCount == 0 ? 1 : byteCount);
  if (byteCount > size) {
    throw ArgumentError.value(value, 'value', 'does not fit in $size bytes');
  }
  final out = Uint8List(size);
  var v = value;
  for (var i = size - 1; i >= 0 && v > BigInt.zero; i--) {
    out[i] = (v & _byteMask).toInt();
    v = v >> 8;
  }
  return out;
}

final BigInt _byteMask = BigInt.from(0xff);

/// Groups a hex fingerprint for display, e.g. `ab12 cd34 …`.
String formatFingerprint(String hex, {int groupSize = 4, int? maxGroups}) {
  final groups = <String>[];
  for (var i = 0; i < hex.length; i += groupSize) {
    groups.add(hex.substring(i, min(i + groupSize, hex.length)));
  }
  if (maxGroups != null && groups.length > maxGroups) {
    return '${groups.take(maxGroups).join(' ')} …';
  }
  return groups.join(' ');
}
