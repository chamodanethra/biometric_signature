import 'dart:convert';
import 'dart:typed_data';

import 'bytes.dart';

/// One `-----BEGIN <label>----- … -----END <label>-----` block.
class PemBlock {
  /// Creates a block.
  const PemBlock(this.label, this.bytes);

  /// The label, e.g. `PUBLIC KEY` or `CERTIFICATE`.
  final String label;

  /// The decoded DER bytes.
  final Uint8List bytes;
}

final RegExp _pemBlock = RegExp(
  r'-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----',
);

/// Encodes [der] as PEM with 64-character lines.
String pemEncode(String label, List<int> der) {
  final b64 = base64.encode(der);
  final lines = <String>[];
  for (var i = 0; i < b64.length; i += 64) {
    lines.add(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
  }
  return '-----BEGIN $label-----\n${lines.join('\n')}\n-----END $label-----';
}

/// Decodes every PEM block in [text], in order.
List<PemBlock> pemDecodeAll(String text) => [
      for (final m in _pemBlock.allMatches(text))
        PemBlock(m.group(1)!, decodeBase64Lenient(m.group(2)!)),
    ];

/// Decodes the first PEM block (optionally requiring [label]).
///
/// Throws [FormatException] when no matching block is found.
Uint8List pemDecode(String text, {String? label}) {
  for (final block in pemDecodeAll(text)) {
    if (label == null || block.label == label) return block.bytes;
  }
  throw FormatException(
    label == null ? 'No PEM block found' : 'No "$label" PEM block found',
  );
}

/// How a public-key string was encoded.
enum PublicKeyEncoding {
  /// `-----BEGIN PUBLIC KEY-----` PEM.
  pem,

  /// Hex-encoded DER.
  hex,

  /// Base64-encoded DER (the plugin's `base64` and `raw` formats).
  base64,
}

/// Detects how the plugin encoded a `publicKey` string.
///
/// A PEM header means PEM. Otherwise a string of hex digits with even length
/// is hex. Everything else is base64. Base64 SPKI always starts with `M`
/// (DER SEQUENCE 0x30), which is not a hex digit, so the rules don't clash.
PublicKeyEncoding detectPublicKeyEncoding(String publicKey) {
  final trimmed = publicKey.trim();
  if (trimmed.contains('-----BEGIN')) return PublicKeyEncoding.pem;
  if (trimmed.isNotEmpty && trimmed.length.isEven && isHexString(trimmed)) {
    return PublicKeyEncoding.hex;
  }
  return PublicKeyEncoding.base64;
}

/// Normalizes a plugin `publicKey` string (base64, PEM or hex) into
/// SubjectPublicKeyInfo DER bytes.
///
/// Every platform returns SPKI DER, only the text encoding differs. Throws
/// [FormatException] when the string cannot be decoded. The result is not
/// validated as SPKI; use `parsePublicKeySpki` for that.
Uint8List publicKeyToSpki(String publicKey) {
  final trimmed = publicKey.trim();
  if (trimmed.isEmpty) {
    throw const FormatException('Public key string is empty');
  }
  switch (detectPublicKeyEncoding(trimmed)) {
    case PublicKeyEncoding.pem:
      final blocks = pemDecodeAll(trimmed);
      if (blocks.isEmpty) {
        throw const FormatException('Malformed PEM public key');
      }
      for (final block in blocks) {
        if (block.label == 'PUBLIC KEY') return block.bytes;
      }
      throw FormatException(
        'Expected a "PUBLIC KEY" PEM block, found "${blocks.first.label}"',
      );
    case PublicKeyEncoding.hex:
      return fromHex(trimmed);
    case PublicKeyEncoding.base64:
      return decodeBase64Lenient(trimmed);
  }
}

/// PEM-encodes SubjectPublicKeyInfo DER.
String spkiToPem(List<int> spki) => pemEncode('PUBLIC KEY', spki);

/// PEM-encodes a certificate.
String certificateToPem(List<int> der) => pemEncode('CERTIFICATE', der);

/// Concatenated PEM for a certificate chain (leaf first).
String certificateChainToPem(List<List<int>> chain) =>
    chain.map(certificateToPem).join('\n');

/// Decodes every `CERTIFICATE` block in [text].
List<Uint8List> certificatesFromPem(String text) => [
      for (final block in pemDecodeAll(text))
        if (block.label == 'CERTIFICATE') block.bytes,
    ];
