import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart' show SecureRandom;

import '../platform/device_platform.dart';
import 'ecies.dart';
import 'hash.dart';
import 'oaep.dart';
import 'public_key.dart';

/// How to encrypt data so that a specific device key can `decrypt()` it.
///
/// Obtain one with [EncryptionTarget.resolve]. The scheme depends on the
/// platform *and* the key, never on a UI toggle.
sealed class EncryptionScheme {
  const EncryptionScheme();

  /// Restores a scheme stored with [toJson].
  factory EncryptionScheme.fromJson(Map<String, dynamic> json) {
    final type = json['type'];
    switch (type) {
      case 'ecies':
        return EciesScheme(
          EciesVariant.values.byName(json['variant'] as String),
          base64.decode(json['publicKeySpki'] as String),
        );
      case 'rsaOaep':
        return RsaOaepScheme(
          (json['mgf1'] as String) == 'sha1'
              ? RsaOaepMgf1.sha1
              : RsaOaepMgf1.sha256,
          base64.decode(json['publicKeySpki'] as String),
        );
      default:
        return UnsupportedScheme(
            json['reason'] as String? ?? 'Unknown scheme "$type"');
    }
  }

  /// Whether [encrypt] can be used.
  bool get isSupported => this is! UnsupportedScheme;

  /// A short name, e.g. `ECIES (Android)`.
  String get label;

  /// A human explanation of the exact parameters.
  String get description;

  /// Encrypts the UTF-8 bytes of [utf8Plaintext].
  ///
  /// The plugin's `decrypt()` always returns UTF-8 text, so binary data must
  /// be base64-encoded first (see `sealEnvelope`). Throws
  /// [UnsupportedError] for an [UnsupportedScheme].
  Uint8List encrypt(String utf8Plaintext, {SecureRandom? random}) =>
      encryptBytes(Uint8List.fromList(utf8.encode(utf8Plaintext)),
          random: random);

  /// Encrypts raw bytes. Only useful if the bytes are valid UTF-8, since
  /// `decrypt()` returns a string.
  Uint8List encryptBytes(Uint8List plaintext, {SecureRandom? random});

  /// [encrypt] then base64, ready for `decrypt(payloadFormat: base64)`.
  String encryptToBase64(String utf8Plaintext, {SecureRandom? random}) =>
      base64.encode(encrypt(utf8Plaintext, random: random));

  /// JSON form, e.g. for a server that records the scheme at registration.
  Map<String, dynamic> toJson();
}

/// ECIES to an EC P-256 key.
final class EciesScheme extends EncryptionScheme {
  /// Creates the scheme.
  const EciesScheme(this.variant, this.publicKeySpki);

  /// Android or Apple key derivation.
  final EciesVariant variant;

  /// Recipient SubjectPublicKeyInfo DER.
  final Uint8List publicKeySpki;

  @override
  String get label => variant == EciesVariant.android
      ? 'ECIES (Android hybrid)'
      : 'ECIES (Apple Secure Enclave)';

  @override
  String get description => variant.description;

  @override
  Uint8List encryptBytes(Uint8List plaintext, {SecureRandom? random}) =>
      eciesEncrypt(publicKeySpki, plaintext, variant, random: random);

  @override
  Map<String, dynamic> toJson() => {
        'type': 'ecies',
        'variant': variant.name,
        'publicKeySpki': base64.encode(publicKeySpki),
      };
}

/// MGF1 digest choice for [RsaOaepScheme].
enum RsaOaepMgf1 {
  /// Android keystore.
  sha1,

  /// Apple.
  sha256,
}

/// RSA-OAEP with SHA-256 and the platform's MGF1 digest.
final class RsaOaepScheme extends EncryptionScheme {
  /// Creates the scheme.
  const RsaOaepScheme(this.mgf1, this.publicKeySpki);

  /// MGF1 digest.
  final RsaOaepMgf1 mgf1;

  /// Recipient SubjectPublicKeyInfo DER.
  final Uint8List publicKeySpki;

  /// The OAEP parameters.
  RsaOaepParameters get parameters => RsaOaepParameters(
        mgf1Hash: mgf1 == RsaOaepMgf1.sha1
            ? HashAlgorithm.sha1
            : HashAlgorithm.sha256,
      );

  @override
  String get label => mgf1 == RsaOaepMgf1.sha1
      ? 'RSA-OAEP (Android keystore)'
      : 'RSA-OAEP (Apple)';

  @override
  String get description {
    final base = '${parameters.description}; at most 190 bytes per message '
        'with RSA-2048';
    return mgf1 == RsaOaepMgf1.sha1
        ? '$base. Works only if the key was created with '
            'enableDecryption: true.'
        : '$base.';
  }

  @override
  Uint8List encryptBytes(Uint8List plaintext, {SecureRandom? random}) {
    final key = ParsedPublicKey.fromSpki(publicKeySpki);
    if (key is! RsaPublicKeyInfo) {
      throw ArgumentError('RSA-OAEP needs an RSA public key');
    }
    return rsaOaepEncrypt(
      key: key,
      message: plaintext,
      params: parameters,
      random: random,
    );
  }

  @override
  Map<String, dynamic> toJson() => {
        'type': 'rsaOaep',
        'mgf1': mgf1.name,
        'publicKeySpki': base64.encode(publicKeySpki),
      };
}

/// The key cannot decrypt on this platform.
final class UnsupportedScheme extends EncryptionScheme {
  /// Creates the scheme.
  const UnsupportedScheme(this.reason);

  /// Why decryption is not possible.
  final String reason;

  @override
  String get label => 'Not supported';

  @override
  String get description => reason;

  @override
  Uint8List encryptBytes(Uint8List plaintext, {SecureRandom? random}) =>
      throw UnsupportedError(reason);

  @override
  Map<String, dynamic> toJson() => {'type': 'unsupported', 'reason': reason};
}

/// Picks the encryption scheme for a device key.
abstract final class EncryptionTarget {
  /// Resolves the scheme from what `createKeys` / `getKeyInfo` returned.
  ///
  /// - **Windows**: unsupported (`decrypt()` returns `notAvailable`).
  /// - **Android**: hybrid mode (`isHybridMode` or a `decryptingPublicKey`)
  ///   → Android ECIES to `decryptingPublicKey`; RSA → OAEP SHA-256 /
  ///   MGF1-SHA-1 to `publicKey`; an EC key without a decrypting key is
  ///   signing-only.
  /// - **iOS / macOS**: EC → Apple ECIES to `publicKey`; RSA → OAEP
  ///   SHA-256 / MGF1-SHA-256 to `decryptingPublicKey ?? publicKey`.
  static EncryptionScheme resolve({
    required DevicePlatform platform,
    String? algorithm,
    String? publicKey,
    String? decryptingPublicKey,
    String? decryptingAlgorithm,
    bool? isHybridMode,
  }) {
    switch (platform) {
      case DevicePlatform.windows:
        return const UnsupportedScheme(
          'Windows Hello keys cannot decrypt: decrypt() returns '
          'notAvailable on Windows.',
        );
      case DevicePlatform.other:
        return const UnsupportedScheme(
            'The plugin does not support this platform.');
      case DevicePlatform.android:
        final hybrid = isHybridMode == true || decryptingPublicKey != null;
        if (hybrid) {
          if (decryptingPublicKey == null) {
            return const UnsupportedScheme(
              'Hybrid mode key without a decryptingPublicKey. Read it again '
              'with getKeyInfo().',
            );
          }
          if (decryptingAlgorithm != null && !_isEc(decryptingAlgorithm)) {
            return UnsupportedScheme(
                'Unexpected decrypting key algorithm "$decryptingAlgorithm".');
          }
          return _ecies(decryptingPublicKey, EciesVariant.android);
        }
        final family = _family(algorithm, publicKey);
        if (family == _KeyFamily.rsa) {
          return _oaep(publicKey!, RsaOaepMgf1.sha1);
        }
        if (family == _KeyFamily.ec) {
          return const UnsupportedScheme(
            'EC signing-only key: it has no decryption key. Recreate it with '
            'enableDecryption: true to get a hybrid ECIES key.',
          );
        }
        return _noKey(publicKey);
      case DevicePlatform.ios:
      case DevicePlatform.macos:
        final family = _family(algorithm, publicKey);
        if (family == _KeyFamily.ec) {
          return _ecies(publicKey!, EciesVariant.apple);
        }
        if (family == _KeyFamily.rsa) {
          return _oaep(decryptingPublicKey ?? publicKey!, RsaOaepMgf1.sha256);
        }
        if (decryptingPublicKey != null) {
          return _oaep(decryptingPublicKey, RsaOaepMgf1.sha256);
        }
        return _noKey(publicKey);
    }
  }

  static EncryptionScheme _noKey(String? publicKey) => UnsupportedScheme(
        publicKey == null
            ? 'No public key available for this key.'
            : 'Unrecognised key algorithm.',
      );

  static bool _isEc(String algorithm) =>
      algorithm.toUpperCase().startsWith('EC');

  static _KeyFamily? _family(String? algorithm, String? publicKey) {
    if (publicKey == null) return null;
    if (algorithm != null) {
      final upper = algorithm.toUpperCase();
      if (upper.startsWith('RSA')) return _KeyFamily.rsa;
      if (upper.startsWith('EC')) return _KeyFamily.ec;
    }
    try {
      return switch (ParsedPublicKey.parse(publicKey)) {
        RsaPublicKeyInfo() => _KeyFamily.rsa,
        EcPublicKeyInfo() => _KeyFamily.ec,
        UnsupportedPublicKey() => null,
      };
    } on FormatException {
      return null;
    }
  }

  static EncryptionScheme _ecies(String publicKey, EciesVariant variant) {
    final ParsedPublicKey key;
    try {
      key = ParsedPublicKey.parse(publicKey);
    } on FormatException catch (e) {
      return UnsupportedScheme('Public key could not be parsed: ${e.message}');
    }
    if (key is! EcPublicKeyInfo || key.curve != EcCurve.p256) {
      return UnsupportedScheme(
          'ECIES needs an EC P-256 key, got ${key.description}.');
    }
    return EciesScheme(variant, key.spki);
  }

  static EncryptionScheme _oaep(String publicKey, RsaOaepMgf1 mgf1) {
    final ParsedPublicKey key;
    try {
      key = ParsedPublicKey.parse(publicKey);
    } on FormatException catch (e) {
      return UnsupportedScheme('Public key could not be parsed: ${e.message}');
    }
    if (key is! RsaPublicKeyInfo) {
      return UnsupportedScheme(
          'RSA-OAEP needs an RSA key, got ${key.description}.');
    }
    return RsaOaepScheme(mgf1, key.spki);
  }
}

enum _KeyFamily { rsa, ec }
