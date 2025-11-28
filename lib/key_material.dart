import 'dart:convert';
import 'dart:typed_data';

/// Supported serialization formats for keys and signatures.
enum KeyFormat { base64, pem, raw, hex }

extension KeyFormatWire on KeyFormat {
  /// Uppercase representation used on the platform channel.
  String get wireValue {
    switch (this) {
      case KeyFormat.base64:
        return 'BASE64';
      case KeyFormat.pem:
        return 'PEM';
      case KeyFormat.raw:
        return 'RAW';
      case KeyFormat.hex:
        return 'HEX';
    }
  }

  /// Parses a [KeyFormat] from its wire representation.
  static KeyFormat? fromWire(String? value) {
    switch (value) {
      case 'BASE64':
        return KeyFormat.base64;
      case 'PEM':
        return KeyFormat.pem;
      case 'RAW':
        return KeyFormat.raw;
      case 'HEX':
        return KeyFormat.hex;
      default:
        return null;
    }
  }
}

/// Holds a value alongside the format it is encoded with.
class FormattedValue {
  const FormattedValue({
    required this.format,
    required this.value,
    this.pemLabel,
  });

  /// The declared format of [value].
  final KeyFormat format;

  /// The PEM label to use when emitting PEM (e.g. `PUBLIC KEY`).
  final String? pemLabel;

  /// Either a [String] or [Uint8List] holding the formatted bytes.
  final Object value;

  /// Returns the underlying bytes, decoding when necessary.
  Uint8List toBytes() {
    if (value is Uint8List) {
      return value as Uint8List;
    }
    final stringValue = value as String;
    switch (format) {
      case KeyFormat.base64:
        return Uint8List.fromList(base64Decode(stringValue));
      case KeyFormat.pem:
        return Uint8List.fromList(base64Decode(_stripPem(stringValue)));
      case KeyFormat.hex:
        return Uint8List.fromList(_decodeHex(stringValue));
      case KeyFormat.raw:
        throw StateError('RAW values must be provided as byte data.');
    }
  }

  /// Returns the contents encoded as base64.
  String toBase64() {
    if (value is String && format == KeyFormat.base64) {
      return value as String;
    }
    return base64Encode(toBytes());
  }

  /// Returns the contents encoded as hexadecimal.
  String toHex({bool uppercase = false}) {
    String source;
    if (value is String && format == KeyFormat.hex) {
      source = value as String;
    } else {
      final bytes = toBytes();
      final buffer = StringBuffer();
      for (final b in bytes) {
        buffer.write(b.toRadixString(16).padLeft(2, '0'));
      }
      source = buffer.toString();
    }
    return uppercase ? source.toUpperCase() : source.toLowerCase();
  }

  /// Returns the contents encoded as a PEM block.
  ///
  /// Throws when [format] is [KeyFormat.raw] and [value] is not UTF-8 data.
  String toPem({String? overrideLabel}) {
    final label = overrideLabel ?? pemLabel ?? 'PUBLIC KEY';
    if (value is String && format == KeyFormat.pem) {
      return _ensurePemLabel(value as String, label);
    }
    final normalized = base64Encode(toBytes());
    final chunked = _chunkBase64(normalized);
    return '-----BEGIN $label-----\n$chunked\n-----END $label-----';
  }

  /// Returns the formatted value as a string if already string-backed.
  String? asString() => value is String ? value as String : null;

  static String _chunkBase64(String input, [int chunkSize = 64]) {
    final buffer = StringBuffer();
    for (var i = 0; i < input.length; i += chunkSize) {
      final end = (i + chunkSize < input.length) ? i + chunkSize : input.length;
      buffer.writeln(input.substring(i, end));
    }
    final result = buffer.toString().trimRight();
    return result;
  }

  static String _stripPem(String pem) {
    return pem
        .replaceAll(RegExp(r'-----BEGIN [^-]+-----'), '')
        .replaceAll(RegExp(r'-----END [^-]+-----'), '')
        .replaceAll(RegExp(r'\s'), '');
  }

  static String _ensurePemLabel(String pem, String label) {
    final stripped = _stripPem(pem);
    final chunked = _chunkBase64(stripped);
    return '-----BEGIN $label-----\n$chunked\n-----END $label-----';
  }

  static List<int> _decodeHex(String input) {
    final sanitized = input.replaceAll(RegExp(r'\s'), '');
    if (sanitized.length % 2 != 0) {
      throw const FormatException('Hex payload must have even length');
    }
    final bytes = <int>[];
    for (var i = 0; i < sanitized.length; i += 2) {
      bytes.add(int.parse(sanitized.substring(i, i + 2), radix: 16));
    }
    return bytes;
  }
}

/// Capture structured response for `createKeys`.
class KeyCreationResult {
  KeyCreationResult({
    required this.publicKey,
    required this.algorithm,
    required this.keySize,
    this.signingPublicKey,
    this.signingAlgorithm,
    this.signingKeySize,
    this.isHybridMode = false,
  });

  /// The primary public key (for encryption in hybrid mode, or general use otherwise)
  final FormattedValue publicKey;

  /// The algorithm of the primary key ("RSA" or "EC")
  final String algorithm;

  /// The size of the primary key in bits
  final int keySize;

  // ========== Hybrid Mode Fields (Android EC + Decryption) ==========

  /// The signing public key (only present in hybrid mode)
  final FormattedValue? signingPublicKey;

  /// The signing algorithm (only present in hybrid mode, typically "EC")
  final String? signingAlgorithm;

  /// The signing key size in bits (only present in hybrid mode, typically 256)
  final int? signingKeySize;

  /// Whether this result is from hybrid mode
  /// In hybrid mode:
  /// - `publicKey` is the encryption key (for ECIES)
  /// - `signingPublicKey` is the signing key (for ECDSA)
  final bool isHybridMode;

  factory KeyCreationResult.fromChannel(Map<String, dynamic> raw) {
    final isHybrid = raw['hybridMode'] == true;

    FormattedValue? signingPubKey;
    if (isHybrid && raw['signingPublicKey'] != null) {
      signingPubKey = FormattedValue(
        format:
            KeyFormatWire.fromWire(raw['signingPublicKeyFormat'] as String?) ??
            KeyFormat.base64,
        value: raw['signingPublicKey']!,
        pemLabel: raw['signingPublicKeyPemLabel'] as String?,
      );
    }

    return KeyCreationResult(
      publicKey: FormattedValue(
        format:
            KeyFormatWire.fromWire(raw['publicKeyFormat'] as String?) ??
            KeyFormat.base64,
        value: raw['publicKey']!,
        pemLabel: raw['publicKeyPemLabel'] as String?,
      ),
      algorithm: (raw['algorithm'] as String?) ?? 'RSA',
      keySize: (raw['keySize'] as num?)?.toInt() ?? 2048,
      signingPublicKey: signingPubKey,
      signingAlgorithm: raw['signingAlgorithm'] as String?,
      signingKeySize: (raw['signingKeySize'] as num?)?.toInt(),
      isHybridMode: isHybrid,
    );
  }

  @override
  String toString() {
    if (isHybridMode) {
      return 'KeyCreationResult(hybrid: encryption=$algorithm/$keySize, signing=$signingAlgorithm/$signingKeySize)';
    }
    return 'KeyCreationResult($algorithm/$keySize)';
  }
}

/// Capture structured response for `createSignature`.
class SignatureResult {
  SignatureResult({
    required this.publicKey,
    required this.signature,
    required this.algorithm,
    required this.keySize,
    this.timestamp,
  });

  final FormattedValue publicKey;
  final FormattedValue signature;
  final String algorithm;
  final int keySize;
  final DateTime? timestamp;

  factory SignatureResult.fromChannel(Map<String, dynamic> raw) {
    final timestampString = raw['timestamp'] as String?;
    return SignatureResult(
      publicKey: FormattedValue(
        format:
            KeyFormatWire.fromWire(raw['publicKeyFormat'] as String?) ??
            KeyFormat.base64,
        value: raw['publicKey']!,
        pemLabel: raw['publicKeyPemLabel'] as String?,
      ),
      signature: FormattedValue(
        format:
            KeyFormatWire.fromWire(raw['signatureFormat'] as String?) ??
            KeyFormat.base64,
        value: raw['signature']!,
        pemLabel: raw['signaturePemLabel'] as String?,
      ),
      algorithm: (raw['algorithm'] as String?) ?? 'RSA',
      keySize: (raw['keySize'] as num?)?.toInt() ?? 2048,
      timestamp: timestampString != null
          ? DateTime.parse(timestampString)
          : null,
    );
  }
}

/// Capture structured response for `decrypt`.
///
/// Contains the decrypted data as a UTF-8 string. Works with both RSA and EC
/// (ECIES) encrypted payloads. The decryption algorithm is automatically
/// selected based on the key type stored on the device.
class DecryptResult {
  DecryptResult({required this.decryptedData});

  /// The decrypted plaintext string (UTF-8 encoded).
  final String decryptedData;

  factory DecryptResult.fromChannel(Map<String, dynamic> raw) {
    return DecryptResult(decryptedData: raw['decryptedData'] as String);
  }
}
