import 'dart:typed_data';

import 'package:pointycastle/api.dart' show PublicKeyParameter;
import 'package:pointycastle/ecc/api.dart' show ECPublicKey, ECSignature;
import 'package:pointycastle/signers/ecdsa_signer.dart';

import '../encoding/bytes.dart';
import '../encoding/der.dart';
import 'hash.dart';
import 'public_key.dart';

/// Signature algorithms the verifier implements.
enum SignatureAlgorithm {
  /// RSASSA-PKCS1-v1_5 with SHA-256 (Android `SHA256withRSA`, Apple
  /// `rsaSignatureMessagePKCS1v15SHA256`, Windows Hello).
  rsaPkcs1Sha256(
      'SHA256withRSA', '1.2.840.113549.1.1.11', HashAlgorithm.sha256),

  /// RSASSA-PKCS1-v1_5 with SHA-384.
  rsaPkcs1Sha384(
      'SHA384withRSA', '1.2.840.113549.1.1.12', HashAlgorithm.sha384),

  /// RSASSA-PKCS1-v1_5 with SHA-512.
  rsaPkcs1Sha512(
      'SHA512withRSA', '1.2.840.113549.1.1.13', HashAlgorithm.sha512),

  /// ECDSA with SHA-256, DER (X9.62) signature (Android `SHA256withECDSA`,
  /// Apple `ecdsaSignatureMessageX962SHA256`).
  ecdsaSha256('SHA256withECDSA', '1.2.840.10045.4.3.2', HashAlgorithm.sha256),

  /// ECDSA with SHA-384.
  ecdsaSha384('SHA384withECDSA', '1.2.840.10045.4.3.3', HashAlgorithm.sha384),

  /// ECDSA with SHA-512.
  ecdsaSha512('SHA512withECDSA', '1.2.840.10045.4.3.4', HashAlgorithm.sha512);

  const SignatureAlgorithm(this.label, this.oid, this.hash);

  /// JCA-style name.
  final String label;

  /// X.509 AlgorithmIdentifier OID.
  final String oid;

  /// The message digest.
  final HashAlgorithm hash;

  /// Whether this is an RSA algorithm.
  bool get isRsa => name.startsWith('rsa');

  /// Whether this is an ECDSA algorithm.
  bool get isEcdsa => name.startsWith('ecdsa');

  /// Looks an algorithm up by OID; `null` when unsupported.
  static SignatureAlgorithm? fromOid(String oid) {
    for (final alg in values) {
      if (alg.oid == oid) return alg;
    }
    return null;
  }

  /// A friendly name for any signature OID, including unsupported ones.
  static String nameForOid(String oid) =>
      fromOid(oid)?.label ?? _otherSignatureOids[oid] ?? oid;

  /// The algorithm the plugin uses for [key]: SHA-256 with RSA PKCS#1 v1.5
  /// or ECDSA. P-384 keys default to SHA-384.
  static SignatureAlgorithm? defaultFor(ParsedPublicKey key) => switch (key) {
        RsaPublicKeyInfo() => rsaPkcs1Sha256,
        EcPublicKeyInfo(curve: EcCurve.p256) => ecdsaSha256,
        EcPublicKeyInfo(curve: EcCurve.p384) => ecdsaSha384,
        UnsupportedPublicKey() => null,
      };
}

const Map<String, String> _otherSignatureOids = {
  '1.2.840.113549.1.1.5': 'SHA1withRSA',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.1': 'SHA1withECDSA',
  '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
  '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
  '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
  '1.3.101.112': 'Ed25519',
};

/// Result of a signature check. Verification never throws.
sealed class VerifyOutcome {
  const VerifyOutcome();

  /// The signature is valid.
  const factory VerifyOutcome.valid() = VerifyValid;

  /// The signature (or its inputs) is invalid.
  const factory VerifyOutcome.invalid(String reason) = VerifyInvalid;

  /// The key or algorithm is not implemented, so nothing was checked.
  const factory VerifyOutcome.unsupported(String reason) = VerifyUnsupported;

  /// Whether the signature verified.
  bool get isValid => this is VerifyValid;

  /// A short explanation suitable for logs and UI.
  String get message;
}

/// A valid signature.
final class VerifyValid extends VerifyOutcome {
  /// Creates the outcome.
  const VerifyValid();

  @override
  String get message => 'Signature is valid';

  @override
  String toString() => 'VerifyOutcome.valid';
}

/// An invalid signature, with the reason.
final class VerifyInvalid extends VerifyOutcome {
  /// Creates the outcome.
  const VerifyInvalid(this.reason);

  /// Why verification failed.
  final String reason;

  @override
  String get message => reason;

  @override
  String toString() => 'VerifyOutcome.invalid($reason)';
}

/// Verification could not be attempted.
final class VerifyUnsupported extends VerifyOutcome {
  /// Creates the outcome.
  const VerifyUnsupported(this.reason);

  /// What is unsupported.
  final String reason;

  @override
  String get message => reason;

  @override
  String toString() => 'VerifyOutcome.unsupported($reason)';
}

/// Verifies a signature produced by the plugin.
///
/// [publicKey] is the plugin's `publicKey` string in any format (base64, PEM
/// or hex). The algorithm defaults to what the plugin uses for that key
/// type. [signature] is the raw signature bytes (decode the plugin's base64
/// or hex `signature` first, or use `signatureBytes`).
VerifyOutcome verifySignature({
  required String publicKey,
  required List<int> message,
  required List<int> signature,
  SignatureAlgorithm? algorithm,
}) {
  final ParsedPublicKey key;
  try {
    key = ParsedPublicKey.parse(publicKey);
  } on FormatException catch (e) {
    return VerifyOutcome.invalid(
        'Public key could not be parsed: ${e.message}');
  }
  return verifySignatureWithKey(
    key,
    message: message,
    signature: signature,
    algorithm: algorithm,
  );
}

/// Verifies [signature] over [message] with an already parsed [key].
VerifyOutcome verifySignatureWithKey(
  ParsedPublicKey key, {
  required List<int> message,
  required List<int> signature,
  SignatureAlgorithm? algorithm,
}) {
  try {
    if (key is UnsupportedPublicKey) {
      return VerifyOutcome.unsupported(key.reason);
    }
    final alg = algorithm ?? SignatureAlgorithm.defaultFor(key);
    if (alg == null) {
      return VerifyOutcome.unsupported(
          'No signature algorithm for ${key.description}');
    }
    final msg = Uint8List.fromList(message);
    final sig = Uint8List.fromList(signature);
    return switch (key) {
      RsaPublicKeyInfo() when alg.isRsa => _verifyRsa(key, alg, msg, sig),
      EcPublicKeyInfo() when alg.isEcdsa => _verifyEcdsa(key, alg, msg, sig),
      _ => VerifyOutcome.invalid(
          'Key type ${key.description} does not match ${alg.label}'),
    };
  } catch (e) {
    return VerifyOutcome.invalid('Verification error: $e');
  }
}

VerifyOutcome _verifyRsa(
  RsaPublicKeyInfo key,
  SignatureAlgorithm alg,
  Uint8List message,
  Uint8List signature,
) {
  final k = key.modulusBytes;
  if (signature.length != k) {
    return VerifyOutcome.invalid(
        'RSA signature must be $k bytes, got ${signature.length}');
  }
  final s = bytesToBigInt(signature);
  if (s >= key.modulus) {
    return const VerifyOutcome.invalid('RSA signature out of range');
  }
  final em = bigIntToBytes(s.modPow(key.exponent, key.modulus), length: k);
  final digest = alg.hash.hash(message);
  // RFC 8017 §9.2: accept DigestInfo with NULL parameters (the standard
  // encoding) or with parameters omitted.
  for (final withNull in const [true, false]) {
    final expected = _emsaPkcs1v15(alg.hash, digest, k, withNull: withNull);
    if (expected != null && constantTimeEquals(em, expected)) {
      return const VerifyOutcome.valid();
    }
  }
  return const VerifyOutcome.invalid('RSA PKCS#1 v1.5 signature mismatch');
}

Uint8List? _emsaPkcs1v15(
  HashAlgorithm hash,
  Uint8List digest,
  int k, {
  required bool withNull,
}) {
  final digestInfo = DerEncoder.sequence([
    DerEncoder.sequence([
      DerEncoder.oid(hash.oid),
      if (withNull) DerEncoder.nullValue(),
    ]),
    DerEncoder.octetString(digest),
  ]);
  final psLength = k - digestInfo.length - 3;
  if (psLength < 8) return null;
  return concatBytes([
    [0x00, 0x01],
    List<int>.filled(psLength, 0xff),
    [0x00],
    digestInfo,
  ]);
}

VerifyOutcome _verifyEcdsa(
  EcPublicKeyInfo key,
  SignatureAlgorithm alg,
  Uint8List message,
  Uint8List signature,
) {
  final EcdsaSignatureValue value;
  try {
    value = EcdsaSignatureValue.fromDer(signature);
  } on FormatException catch (e) {
    return VerifyOutcome.invalid('Malformed ECDSA signature: ${e.message}');
  }
  final n = key.curve.domain.n;
  if (value.r <= BigInt.zero ||
      value.r >= n ||
      value.s <= BigInt.zero ||
      value.s >= n) {
    return const VerifyOutcome.invalid('ECDSA r or s out of range');
  }
  // The digest is computed here; pointycastle truncates it to the curve
  // order's bit length (needed for e.g. P-256 keys signing with SHA-384).
  final digest = alg.hash.hash(message);
  final signer = ECDSASigner()
    ..init(false, PublicKeyParameter<ECPublicKey>(key.toPointyCastle()));
  // High-S signatures are accepted: neither Android nor Apple normalizes S.
  final ok = signer.verifySignature(digest, ECSignature(value.r, value.s));
  return ok
      ? const VerifyOutcome.valid()
      : const VerifyOutcome.invalid('ECDSA signature mismatch');
}

/// The (r, s) pair of an ECDSA signature.
class EcdsaSignatureValue {
  /// Creates a value.
  const EcdsaSignatureValue(this.r, this.s);

  /// Parses a DER `SEQUENCE { INTEGER r, INTEGER s }`.
  factory EcdsaSignatureValue.fromDer(List<int> der) {
    final fields = DerObject.parse(Uint8List.fromList(der)).asSequence();
    if (fields.length != 2) {
      throw const FormatException('ECDSA signature must have two integers');
    }
    return EcdsaSignatureValue(fields[0].asBigInt(), fields[1].asBigInt());
  }

  /// r.
  final BigInt r;

  /// s.
  final BigInt s;

  /// DER encoding.
  Uint8List toDer() => DerEncoder.sequence([
        DerEncoder.integer(r),
        DerEncoder.integer(s),
      ]);

  /// Whether s is above n/2 (valid, but not "low-S" normalized).
  bool isHighS(EcCurve curve) => s > (curve.domain.n >> 1);

  /// The equally valid signature with s replaced by n - s.
  EcdsaSignatureValue flipS(EcCurve curve) =>
      EcdsaSignatureValue(r, curve.domain.n - s);
}
