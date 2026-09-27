import 'dart:typed_data';

import 'package:pointycastle/api.dart' show SecureRandom;
import 'package:pointycastle/ecc/api.dart' show ECPoint;

import '../encoding/bytes.dart';
import '../encoding/der.dart';
import 'hash.dart';
import 'public_key.dart';
import 'signature_verifier.dart';

/// A software EC key pair. Used by the fake platform, tests and synthetic
/// certificates — never as a stand-in for a hardware key in a real app.
class SoftwareEcKeyPair {
  /// Wraps an existing private scalar [d] on [curve].
  SoftwareEcKeyPair.fromPrivateScalar(this.curve, this.d) {
    if (d <= BigInt.zero || d >= curve.domain.n) {
      throw ArgumentError.value(d, 'd', 'private scalar out of range');
    }
  }

  /// Generates a fresh key pair.
  factory SoftwareEcKeyPair.generate({
    EcCurve curve = EcCurve.p256,
    SecureRandom? random,
  }) =>
      SoftwareEcKeyPair.fromPrivateScalar(
          curve, randomScalar(curve, random: random));

  /// The curve.
  final EcCurve curve;

  /// The private scalar.
  final BigInt d;

  late final ECPoint _q = (curve.domain.G * d)!;

  /// The public key.
  late final EcPublicKeyInfo publicKey =
      EcPublicKeyInfo.fromPoint(curve, encodeUncompressedPoint(curve, _q));

  /// SubjectPublicKeyInfo DER of the public key.
  Uint8List get spki => publicKey.spki;

  /// Signs [message] with ECDSA and returns a DER signature.
  ///
  /// [hash] defaults to SHA-256 for P-256 and SHA-384 for P-384.
  Uint8List sign(List<int> message,
      {HashAlgorithm? hash, SecureRandom? random}) {
    final h = hash ??
        (curve == EcCurve.p384 ? HashAlgorithm.sha384 : HashAlgorithm.sha256);
    final n = curve.domain.n;
    final e = _truncatedHash(h.hash(message), n);
    while (true) {
      final k = randomScalar(curve, random: random);
      final r = (curve.domain.G * k)!.x!.toBigInteger()! % n;
      if (r == BigInt.zero) continue;
      final s = (k.modInverse(n) * (e + d * r)) % n;
      if (s == BigInt.zero) continue;
      return EcdsaSignatureValue(r, s).toDer();
    }
  }

  /// ECDH: the x-coordinate of `d * peer`, as fixed-length bytes.
  ///
  /// [peer] must already be validated (see [decodeEcPoint]).
  Uint8List sharedSecret(ECPoint peer) {
    final shared = (peer * d)!;
    if (shared.isInfinity) {
      throw StateError('ECDH produced the point at infinity');
    }
    return bigIntToBytes(shared.x!.toBigInteger()!, length: curve.fieldBytes);
  }

  /// The private key as Apple's `SecKeyCopyExternalRepresentation` format:
  /// `04 || X || Y || D`.
  Uint8List toX963PrivateRepresentation() => concatBytes([
        publicKey.uncompressedPoint,
        bigIntToBytes(d, length: curve.fieldBytes),
      ]);
}

BigInt _truncatedHash(Uint8List digest, BigInt n) {
  var e = bytesToBigInt(digest);
  final excess = digest.length * 8 - n.bitLength;
  if (excess > 0) e = e >> excess;
  return e;
}

/// A uniformly distributed scalar in `[1, n-1]` for [curve].
BigInt randomScalar(EcCurve curve, {SecureRandom? random}) {
  final n = curve.domain.n;
  final bytes = random?.nextBytes(curve.fieldBytes + 8) ??
      secureRandomBytes(curve.fieldBytes + 8);
  return (bytesToBigInt(bytes) % (n - BigInt.one)) + BigInt.one;
}

/// A software RSA key pair (CRT form).
class SoftwareRsaKeyPair {
  /// Creates a key from its components. Throws if `p * q != modulus`.
  SoftwareRsaKeyPair({
    required this.modulus,
    required this.publicExponent,
    required this.privateExponent,
    required this.p,
    required this.q,
  }) {
    if (p * q != modulus) {
      throw ArgumentError('RSA modulus does not equal p * q');
    }
  }

  /// n.
  final BigInt modulus;

  /// e.
  final BigInt publicExponent;

  /// d.
  final BigInt privateExponent;

  /// First prime.
  final BigInt p;

  /// Second prime.
  final BigInt q;

  late final BigInt _dP = privateExponent % (p - BigInt.one);
  late final BigInt _dQ = privateExponent % (q - BigInt.one);
  late final BigInt _qInv = q.modInverse(p);

  /// The public key.
  late final RsaPublicKeyInfo publicKey =
      RsaPublicKeyInfo.fromComponents(modulus, publicExponent);

  /// SubjectPublicKeyInfo DER of the public key.
  Uint8List get spki => publicKey.spki;

  /// Modulus length in bytes.
  int get modulusBytes => (modulus.bitLength + 7) ~/ 8;

  /// The RSA private-key primitive `x^d mod n`, using the CRT.
  BigInt privateOp(BigInt x) {
    if (x >= modulus || x.isNegative) {
      throw ArgumentError('RSA input out of range');
    }
    final m1 = x.modPow(_dP, p);
    final m2 = x.modPow(_dQ, q);
    final h = (_qInv * (m1 - m2)) % p;
    return m2 + h * q;
  }

  /// RSASSA-PKCS1-v1_5 signature over [message].
  Uint8List sign(List<int> message,
      {HashAlgorithm hash = HashAlgorithm.sha256}) {
    final digestInfo = DerEncoder.sequence([
      DerEncoder.sequence([DerEncoder.oid(hash.oid), DerEncoder.nullValue()]),
      DerEncoder.octetString(hash.hash(message)),
    ]);
    final k = modulusBytes;
    final psLength = k - digestInfo.length - 3;
    if (psLength < 8) {
      throw ArgumentError('RSA key too small for ${hash.label}');
    }
    final em = concatBytes([
      [0x00, 0x01],
      List<int>.filled(psLength, 0xff),
      [0x00],
      digestInfo,
    ]);
    return bigIntToBytes(privateOp(bytesToBigInt(em)), length: k);
  }

  /// Parses PKCS#1 `RSAPrivateKey` DER (`openssl rsa -traditional`).
  factory SoftwareRsaKeyPair.fromPkcs1Der(Uint8List der) {
    final f = DerObject.parse(der).asSequence();
    if (f.length < 6) {
      throw const FormatException('RSAPrivateKey has too few fields');
    }
    return SoftwareRsaKeyPair(
      modulus: f[1].asBigInt(),
      publicExponent: f[2].asBigInt(),
      privateExponent: f[3].asBigInt(),
      p: f[4].asBigInt(),
      q: f[5].asBigInt(),
    );
  }

  /// Parses PKCS#8 `PrivateKeyInfo` DER wrapping an RSA key
  /// (`openssl genpkey` output).
  factory SoftwareRsaKeyPair.fromPkcs8Der(Uint8List der) {
    final f = DerObject.parse(der).asSequence();
    if (f.length < 3) {
      throw const FormatException('PrivateKeyInfo has too few fields');
    }
    final oid = f[1].asSequence().first.asOid();
    if (oid != KeyOids.rsaEncryption) {
      throw FormatException('Not an RSA PrivateKeyInfo: $oid');
    }
    return SoftwareRsaKeyPair.fromPkcs1Der(f[2].asOctetString());
  }
}
