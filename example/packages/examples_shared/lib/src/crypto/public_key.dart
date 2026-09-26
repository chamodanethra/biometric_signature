import 'dart:convert' show Base64Codec;
import 'dart:typed_data';

import 'package:pointycastle/asymmetric/api.dart' show RSAPublicKey;
import 'package:pointycastle/ecc/api.dart'
    show ECDomainParameters, ECPoint, ECPublicKey;
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/ecc/curves/secp384r1.dart';

import '../encoding/bytes.dart';
import '../encoding/der.dart';
import '../encoding/pem.dart';

/// Object identifiers used for public keys.
abstract final class KeyOids {
  /// rsaEncryption.
  static const String rsaEncryption = '1.2.840.113549.1.1.1';

  /// id-ecPublicKey.
  static const String ecPublicKey = '1.2.840.10045.2.1';

  /// secp256r1 / prime256v1 / P-256.
  static const String p256 = '1.2.840.10045.3.1.7';

  /// secp384r1 / P-384.
  static const String p384 = '1.3.132.0.34';

  /// Friendly names for OIDs that show up in attestation chains but are not
  /// supported by this package (e.g. post-quantum keys).
  static const Map<String, String> knownUnsupported = {
    '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
    '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
    '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
    '1.3.101.112': 'Ed25519',
    '1.3.101.110': 'X25519',
    '1.3.132.0.35': 'P-521',
  };
}

/// Supported elliptic curves.
enum EcCurve {
  /// NIST P-256 (secp256r1), used by every platform's EC keys.
  p256('P-256', KeyOids.p256, 32),

  /// NIST P-384 (secp384r1), used by some attestation intermediates and the
  /// 2025 Google attestation root.
  p384('P-384', KeyOids.p384, 48);

  const EcCurve(this.label, this.oid, this.fieldBytes);

  /// Display name.
  final String label;

  /// Named-curve OID.
  final String oid;

  /// Size of a field element / coordinate in bytes.
  final int fieldBytes;

  /// Key size in bits.
  int get bits => fieldBytes * 8;

  /// pointycastle domain parameters (cached).
  ECDomainParameters get domain => switch (this) {
        EcCurve.p256 => _p256Domain,
        EcCurve.p384 => _p384Domain,
      };

  /// Looks a curve up by OID.
  static EcCurve? fromOid(String oid) {
    for (final curve in values) {
      if (curve.oid == oid) return curve;
    }
    return null;
  }
}

final ECDomainParameters _p256Domain = ECCurve_secp256r1();
final ECDomainParameters _p384Domain = ECCurve_secp384r1();

/// A parsed SubjectPublicKeyInfo.
///
/// Every `publicKey` string the plugin returns is SPKI DER in some text
/// encoding; [ParsedPublicKey.parse] accepts any of them.
sealed class ParsedPublicKey {
  const ParsedPublicKey(this.spki);

  /// Parses a plugin `publicKey` string (base64, PEM or hex).
  ///
  /// Throws [FormatException] if the string or its DER is malformed. An
  /// algorithm this package does not implement yields an
  /// [UnsupportedPublicKey] rather than an exception.
  factory ParsedPublicKey.parse(String publicKey) =>
      ParsedPublicKey.fromSpki(publicKeyToSpki(publicKey));

  /// Parses SubjectPublicKeyInfo DER.
  factory ParsedPublicKey.fromSpki(Uint8List spki) {
    try {
      return _parseSpki(spki);
    } on FormatException {
      rethrow;
    } catch (e) {
      throw FormatException('Malformed SubjectPublicKeyInfo: $e');
    }
  }

  static ParsedPublicKey _parseSpki(Uint8List spki) {
    final root = DerObject.parse(spki);
    final fields = root.asSequence();
    if (fields.length != 2) {
      throw const FormatException('SubjectPublicKeyInfo must have 2 fields');
    }
    final algId = fields[0].asSequence();
    if (algId.isEmpty) {
      throw const FormatException('AlgorithmIdentifier is empty');
    }
    final oid = algId[0].asOid();
    final keyBits = fields[1].asBitString();
    switch (oid) {
      case KeyOids.rsaEncryption:
        final rsa = DerObject.parse(keyBits.bytes).asSequence();
        if (rsa.length != 2) {
          throw const FormatException('RSAPublicKey must have 2 fields');
        }
        final modulus = rsa[0].asBigInt();
        final exponent = rsa[1].asBigInt();
        if (modulus <= BigInt.zero || exponent <= BigInt.zero) {
          throw const FormatException('RSA modulus/exponent must be positive');
        }
        return RsaPublicKeyInfo._(spki, modulus, exponent);
      case KeyOids.ecPublicKey:
        if (algId.length < 2 || !algId[1].isUniversal(DerTag.oid)) {
          return UnsupportedPublicKey._(
            spki,
            oid,
            'EC key without a named curve is not supported',
          );
        }
        final curveOid = algId[1].asOid();
        final curve = EcCurve.fromOid(curveOid);
        if (curve == null) {
          final name = KeyOids.knownUnsupported[curveOid] ?? curveOid;
          return UnsupportedPublicKey._(
            spki,
            oid,
            'EC curve $name is not supported',
          );
        }
        final point = decodeEcPoint(curve, keyBits.bytes);
        return EcPublicKeyInfo._(spki, curve, point);
      default:
        final name = KeyOids.knownUnsupported[oid] ?? oid;
        return UnsupportedPublicKey._(
          spki,
          oid,
          'Public-key algorithm $name is not supported',
        );
    }
  }

  /// The SubjectPublicKeyInfo DER bytes.
  final Uint8List spki;

  /// Algorithm family, e.g. `RSA` or `EC`.
  String get algorithm;

  /// Key size in bits (0 when unknown).
  int get keySizeBits;

  /// Human-readable summary, e.g. `EC P-256` or `RSA 2048`.
  String get description;

  /// SHA-256 of the SPKI DER.
  Uint8List get spkiSha256 => sha256Bytes(spki);

  /// SHA-256 of the SPKI DER as lower-case hex (a stable key fingerprint).
  String get fingerprint => toHex(spkiSha256);

  /// Base64 of the SPKI DER (the plugin's default `publicKey` format).
  String get base64 => toBase64(spki);

  /// PEM of the SPKI DER.
  String toPem() => spkiToPem(spki);

  /// Whether [other] is the same key material, ignoring encoding details.
  bool sameKeyAs(ParsedPublicKey other);

  /// Base64 helper that avoids importing `dart:convert` at call sites.
  static String toBase64(List<int> bytes) => _b64.encode(bytes);
}

const _b64 = Base64Codec();

/// An RSA public key.
final class RsaPublicKeyInfo extends ParsedPublicKey {
  RsaPublicKeyInfo._(super.spki, this.modulus, this.exponent);

  /// Builds SPKI DER for an RSA key and parses it.
  factory RsaPublicKeyInfo.fromComponents(BigInt modulus, BigInt exponent) =>
      ParsedPublicKey.fromSpki(encodeRsaSpki(modulus, exponent))
          as RsaPublicKeyInfo;

  /// The modulus n.
  final BigInt modulus;

  /// The public exponent e.
  final BigInt exponent;

  /// Modulus length in bytes (k in RFC 8017).
  int get modulusBytes => (modulus.bitLength + 7) ~/ 8;

  @override
  String get algorithm => 'RSA';

  @override
  int get keySizeBits => modulus.bitLength;

  @override
  String get description => 'RSA $keySizeBits';

  /// pointycastle form.
  RSAPublicKey toPointyCastle() => RSAPublicKey(modulus, exponent);

  @override
  bool sameKeyAs(ParsedPublicKey other) =>
      other is RsaPublicKeyInfo &&
      other.modulus == modulus &&
      other.exponent == exponent;
}

/// An EC public key on a supported curve.
final class EcPublicKeyInfo extends ParsedPublicKey {
  EcPublicKeyInfo._(super.spki, this.curve, this.point);

  /// Builds SPKI DER for an uncompressed point and parses it.
  factory EcPublicKeyInfo.fromPoint(EcCurve curve, Uint8List uncompressed) =>
      ParsedPublicKey.fromSpki(encodeEcSpki(curve, uncompressed))
          as EcPublicKeyInfo;

  /// The curve.
  final EcCurve curve;

  /// The validated point.
  final ECPoint point;

  /// The point in uncompressed X9.62 form (`04 || X || Y`).
  Uint8List get uncompressedPoint => encodeUncompressedPoint(curve, point);

  @override
  String get algorithm => 'EC';

  @override
  int get keySizeBits => curve.bits;

  @override
  String get description => 'EC ${curve.label}';

  /// pointycastle form.
  ECPublicKey toPointyCastle() => ECPublicKey(point, curve.domain);

  @override
  bool sameKeyAs(ParsedPublicKey other) =>
      other is EcPublicKeyInfo &&
      other.curve == curve &&
      constantTimeEquals(other.uncompressedPoint, uncompressedPoint);
}

/// A syntactically valid SPKI whose algorithm is not implemented here
/// (for example an ML-DSA key in a newer attestation chain).
final class UnsupportedPublicKey extends ParsedPublicKey {
  UnsupportedPublicKey._(super.spki, this.algorithmOid, this.reason);

  /// The algorithm OID from the SPKI.
  final String algorithmOid;

  /// Why the key is unsupported.
  final String reason;

  @override
  String get algorithm =>
      KeyOids.knownUnsupported[algorithmOid] ?? algorithmOid;

  @override
  int get keySizeBits => 0;

  @override
  String get description => '$algorithm (unsupported)';

  @override
  bool sameKeyAs(ParsedPublicKey other) =>
      other is UnsupportedPublicKey && constantTimeEquals(other.spki, spki);
}

/// Decodes and validates an X9.62 point (uncompressed or compressed).
///
/// Throws [FormatException] if the encoding is wrong or the point is not on
/// the curve (an invalid-curve point must never be used for ECDH).
ECPoint decodeEcPoint(EcCurve curve, List<int> encoded) {
  if (encoded.isEmpty) {
    throw const FormatException('Empty EC point');
  }
  final ECPoint? point;
  try {
    point = curve.domain.curve.decodePoint(encoded);
  } on ArgumentError catch (e) {
    throw FormatException('Invalid EC point encoding: ${e.message}');
  }
  if (point == null || point.isInfinity) {
    throw const FormatException('EC point is the point at infinity');
  }
  final x = point.x!.toBigInteger()!;
  final y = point.y!.toBigInteger()!;
  final p = _fieldPrime(curve);
  if (x >= p || y >= p) {
    throw const FormatException('EC coordinate out of range');
  }
  final a = curve.domain.curve.a!.toBigInteger()!;
  final b = curve.domain.curve.b!.toBigInteger()!;
  final lhs = (y * y) % p;
  final rhs = (x * x * x + a * x + b) % p;
  if (lhs != rhs) {
    throw const FormatException('EC point is not on the curve');
  }
  return point;
}

BigInt _fieldPrime(EcCurve curve) => switch (curve) {
      EcCurve.p256 => BigInt.parse(
          'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
          radix: 16),
      EcCurve.p384 => BigInt.parse(
          'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe'
          'ffffffff0000000000000000ffffffff',
          radix: 16),
    };

/// Encodes [point] as `04 || X || Y`.
Uint8List encodeUncompressedPoint(EcCurve curve, ECPoint point) => concatBytes([
      [0x04],
      bigIntToBytes(point.x!.toBigInteger()!, length: curve.fieldBytes),
      bigIntToBytes(point.y!.toBigInteger()!, length: curve.fieldBytes),
    ]);

/// SubjectPublicKeyInfo DER for an EC key.
Uint8List encodeEcSpki(EcCurve curve, List<int> uncompressedPoint) =>
    DerEncoder.sequence([
      DerEncoder.sequence([
        DerEncoder.oid(KeyOids.ecPublicKey),
        DerEncoder.oid(curve.oid),
      ]),
      DerEncoder.bitString(uncompressedPoint),
    ]);

/// SubjectPublicKeyInfo DER for an RSA key.
Uint8List encodeRsaSpki(BigInt modulus, BigInt exponent) =>
    DerEncoder.sequence([
      DerEncoder.sequence([
        DerEncoder.oid(KeyOids.rsaEncryption),
        DerEncoder.nullValue(),
      ]),
      DerEncoder.bitString(DerEncoder.sequence([
        DerEncoder.integer(modulus),
        DerEncoder.integer(exponent),
      ])),
    ]);
