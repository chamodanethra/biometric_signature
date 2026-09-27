import 'dart:typed_data';

import '../crypto/public_key.dart';
import '../crypto/signature_verifier.dart';
import '../encoding/bytes.dart';
import '../encoding/der.dart';
import '../encoding/pem.dart';

/// A certificate could not be parsed.
class CertificateParseException extends FormatException {
  /// Creates the exception.
  const CertificateParseException(super.message);

  @override
  String toString() => 'CertificateParseException: $message';
}

/// Well-known extension OIDs.
abstract final class X509Oids {
  /// Android key attestation (KeyDescription).
  static const String keyAttestation = '1.3.6.1.4.1.11129.2.1.17';

  /// Android remote provisioning info.
  static const String provisioningInfo = '1.3.6.1.4.1.11129.2.1.30';

  /// basicConstraints.
  static const String basicConstraints = '2.5.29.19';

  /// keyUsage.
  static const String keyUsage = '2.5.29.15';
}

const Map<String, String> _attributeNames = {
  '2.5.4.3': 'CN',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'title',
  '1.2.840.113549.1.9.1': 'emailAddress',
};

/// One attribute of a distinguished name.
class DnAttribute {
  /// Creates an attribute.
  const DnAttribute(this.oid, this.value);

  /// Attribute type OID.
  final String oid;

  /// Decoded value (hex with a `#` prefix if it is not a string).
  final String value;

  /// Short name such as `CN`, `O` or `serialNumber` (the OID if unknown).
  String get shortName => _attributeNames[oid] ?? oid;

  @override
  String toString() => '$shortName=$value';
}

/// A parsed X.501 Name. Attestation certificates often identify devices
/// with the `serialNumber` and `title` attributes rather than `CN`.
class DistinguishedName {
  /// Creates a name from its attributes in encoded order.
  const DistinguishedName(this.attributes);

  /// Attributes in encoded order (RDNs flattened).
  final List<DnAttribute> attributes;

  String? _first(String oid) {
    for (final a in attributes) {
      if (a.oid == oid) return a.value;
    }
    return null;
  }

  /// Common name.
  String? get commonName => _first('2.5.4.3');

  /// Organization.
  String? get organization => _first('2.5.4.10');

  /// The `serialNumber` attribute (not the certificate serial).
  String? get serialNumber => _first('2.5.4.5');

  /// Title.
  String? get title => _first('2.5.4.12');

  @override
  String toString() => attributes.isEmpty ? '(empty)' : attributes.join(', ');

  /// Whether [other] names the same entity: same attribute types in the
  /// same order, values equal ignoring case and repeated whitespace (a
  /// simplified RFC 5280 §7.1 comparison, for issuers that re-encode a name
  /// with a different string type).
  bool equivalentTo(DistinguishedName other) {
    if (attributes.length != other.attributes.length) return false;
    String norm(String v) =>
        v.trim().replaceAll(RegExp(r'\s+'), ' ').toLowerCase();
    for (var i = 0; i < attributes.length; i++) {
      final a = attributes[i];
      final b = other.attributes[i];
      if (a.oid != b.oid || norm(a.value) != norm(b.value)) return false;
    }
    return true;
  }
}

/// basicConstraints extension.
class BasicConstraints {
  /// Creates the value.
  const BasicConstraints({required this.isCa, this.pathLength});

  /// Whether the subject is a CA.
  final bool isCa;

  /// Maximum number of intermediate CAs below this one.
  final int? pathLength;
}

/// An X.509 extension.
class X509Extension {
  /// Creates an extension.
  const X509Extension(this.oid, this.critical, this.value);

  /// Extension OID.
  final String oid;

  /// Critical flag.
  final bool critical;

  /// The extnValue OCTET STRING content (DER of the extension value).
  final Uint8List value;
}

/// A parsed X.509 v1–v3 certificate that keeps the raw bytes needed to
/// check signatures (the exact TBS portion) and compare names.
class X509Certificate {
  X509Certificate._({
    required this.der,
    required this.tbsRaw,
    required this.version,
    required this.serialNumber,
    required this.tbsSignatureAlgorithmOid,
    required this.issuerRaw,
    required this.issuer,
    required this.notBefore,
    required this.notAfter,
    required this.subjectRaw,
    required this.subject,
    required this.spkiRaw,
    required this.publicKey,
    required this.extensions,
    required this.signatureAlgorithmOid,
    required this.signatureValue,
  });

  /// Parses DER. Throws [CertificateParseException] for malformed input;
  /// unsupported key or signature algorithms parse fine and are reported by
  /// [publicKey] / [signatureAlgorithm].
  factory X509Certificate.parse(Uint8List der) {
    try {
      return _parse(der);
    } on CertificateParseException {
      rethrow;
    } on FormatException catch (e) {
      throw CertificateParseException(e.message);
    } catch (e) {
      throw CertificateParseException('Malformed certificate: $e');
    }
  }

  /// Parses every `CERTIFICATE` block of a PEM text, in order.
  static List<X509Certificate> parsePemChain(String pem) =>
      certificatesFromPem(pem).map(X509Certificate.parse).toList();

  static X509Certificate _parse(Uint8List der) {
    final top = DerObject.parse(der).asSequence();
    if (top.length != 3) {
      throw const CertificateParseException(
          'Certificate must have 3 top-level fields');
    }
    final tbs = top[0];
    final tbsFields = tbs.asSequence();
    var i = 0;
    var version = 1;
    if (tbsFields.isNotEmpty && tbsFields[0].isContext(0)) {
      version = tbsFields[0].explicitInner().asInt() + 1;
      i++;
    }
    if (tbsFields.length < i + 6) {
      throw const CertificateParseException('TBSCertificate is truncated');
    }
    final serial = tbsFields[i++].asBigInt();
    final tbsSigAlg = _algorithmOid(tbsFields[i++]);
    final issuerObj = tbsFields[i++];
    final validity = tbsFields[i++].asSequence();
    if (validity.length != 2) {
      throw const CertificateParseException('Validity must have 2 fields');
    }
    final subjectObj = tbsFields[i++];
    final spkiObj = tbsFields[i++];
    final extensions = <String, X509Extension>{};
    for (; i < tbsFields.length; i++) {
      final field = tbsFields[i];
      if (field.isContext(3)) {
        for (final ext in field.explicitInner().asSequence()) {
          final parts = ext.asSequence();
          if (parts.length < 2 || parts.length > 3) {
            throw const CertificateParseException('Malformed extension');
          }
          final oid = parts[0].asOid();
          final critical = parts.length == 3 && parts[1].asBool();
          final value = parts.last.asOctetString();
          if (extensions.containsKey(oid)) {
            throw CertificateParseException('Duplicate extension $oid');
          }
          extensions[oid] = X509Extension(oid, critical, value);
        }
      }
    }
    final ParsedPublicKey publicKey;
    try {
      publicKey = ParsedPublicKey.fromSpki(spkiObj.encoded);
    } on FormatException catch (e) {
      throw CertificateParseException(
          'Malformed subject public key: ${e.message}');
    }
    final sigBits = top[2].asBitString();
    if (sigBits.unusedBits != 0) {
      throw const CertificateParseException(
          'Signature BIT STRING has unused bits');
    }
    return X509Certificate._(
      der: der,
      tbsRaw: tbs.encoded,
      version: version,
      serialNumber: serial,
      tbsSignatureAlgorithmOid: tbsSigAlg,
      issuerRaw: issuerObj.encoded,
      issuer: _parseName(issuerObj),
      notBefore: validity[0].asTime(),
      notAfter: validity[1].asTime(),
      subjectRaw: subjectObj.encoded,
      subject: _parseName(subjectObj),
      spkiRaw: spkiObj.encoded,
      publicKey: publicKey,
      extensions: Map.unmodifiable(extensions),
      signatureAlgorithmOid: _algorithmOid(top[1]),
      signatureValue: sigBits.bytes,
    );
  }

  static String _algorithmOid(DerObject algId) {
    final parts = algId.asSequence();
    if (parts.isEmpty) {
      throw const CertificateParseException('Empty AlgorithmIdentifier');
    }
    return parts[0].asOid();
  }

  static DistinguishedName _parseName(DerObject name) {
    final attributes = <DnAttribute>[];
    for (final rdn in name.asSequence()) {
      for (final atv in rdn.asSet()) {
        final parts = atv.asSequence();
        if (parts.length != 2) {
          throw const CertificateParseException('Malformed name attribute');
        }
        String value;
        try {
          value = parts[1].asString();
        } on FormatException {
          value = '#${toHex(parts[1].encoded)}';
        }
        attributes.add(DnAttribute(parts[0].asOid(), value));
      }
    }
    return DistinguishedName(List.unmodifiable(attributes));
  }

  /// The full DER encoding.
  final Uint8List der;

  /// The exact DER of TBSCertificate: the bytes the issuer signed.
  final Uint8List tbsRaw;

  /// X.509 version (1–3).
  final int version;

  /// Certificate serial number.
  final BigInt serialNumber;

  /// Signature algorithm OID repeated inside the TBS.
  final String tbsSignatureAlgorithmOid;

  /// Raw issuer Name DER (compare with the issuer's [subjectRaw]).
  final Uint8List issuerRaw;

  /// Parsed issuer.
  final DistinguishedName issuer;

  /// Start of validity.
  final DateTime notBefore;

  /// End of validity.
  final DateTime notAfter;

  /// Raw subject Name DER.
  final Uint8List subjectRaw;

  /// Parsed subject.
  final DistinguishedName subject;

  /// Raw SubjectPublicKeyInfo DER.
  final Uint8List spkiRaw;

  /// The subject public key ([UnsupportedPublicKey] for e.g. ML-DSA).
  final ParsedPublicKey publicKey;

  /// Extensions by OID.
  final Map<String, X509Extension> extensions;

  /// Outer signature algorithm OID.
  final String signatureAlgorithmOid;

  /// The signature bytes.
  final Uint8List signatureValue;

  /// The signature algorithm, or `null` if unsupported.
  SignatureAlgorithm? get signatureAlgorithm =>
      SignatureAlgorithm.fromOid(signatureAlgorithmOid);

  /// Friendly signature algorithm name (the OID if unknown).
  String get signatureAlgorithmName =>
      SignatureAlgorithm.nameForOid(signatureAlgorithmOid);

  /// RFC 5280 requires the inner and outer algorithm identifiers to match.
  bool get signatureAlgorithmsMatch =>
      signatureAlgorithmOid == tbsSignatureAlgorithmOid;

  /// The extension with [oid], if present.
  X509Extension? extension(String oid) => extensions[oid];

  /// Whether the Android key attestation extension is present.
  bool get hasKeyAttestationExtension =>
      extensions.containsKey(X509Oids.keyAttestation);

  /// Parsed basicConstraints, if present and well formed.
  BasicConstraints? get basicConstraints {
    final ext = extensions[X509Oids.basicConstraints];
    if (ext == null) return null;
    try {
      final fields = DerObject.parse(ext.value).asSequence();
      var isCa = false;
      int? pathLength;
      for (final f in fields) {
        if (f.isUniversal(DerTag.boolean)) isCa = f.asBool();
        if (f.isUniversal(DerTag.integer)) pathLength = f.asInt();
      }
      return BasicConstraints(isCa: isCa, pathLength: pathLength);
    } on FormatException {
      return null;
    }
  }

  /// SHA-256 of the whole certificate.
  Uint8List get sha256Fingerprint => sha256Bytes(der);

  /// SHA-256 of the SubjectPublicKeyInfo (how trust anchors are matched).
  Uint8List get spkiSha256 => sha256Bytes(spkiRaw);

  /// Whether subject and issuer name the same entity.
  bool get isSelfIssued => isIssuedBy(this);

  /// Whether this certificate's issuer name matches [issuer]'s subject
  /// (byte-identical, or equivalent per [DistinguishedName.equivalentTo]).
  bool isIssuedBy(X509Certificate issuer) =>
      constantTimeEquals(issuerRaw, issuer.subjectRaw) ||
      this.issuer.equivalentTo(issuer.subject);

  /// Whether [at] is within [notBefore]..[notAfter] (inclusive).
  bool isValidAt(DateTime at) =>
      !at.isBefore(notBefore) && !at.isAfter(notAfter);

  /// Checks this certificate's signature with [issuerKey]. Never throws.
  VerifyOutcome verifySignedBy(ParsedPublicKey issuerKey) {
    final alg = signatureAlgorithm;
    if (alg == null) {
      return VerifyOutcome.unsupported(
          'Unsupported signature algorithm $signatureAlgorithmName');
    }
    return verifySignatureWithKey(
      issuerKey,
      message: tbsRaw,
      signature: signatureValue,
      algorithm: alg,
    );
  }

  /// PEM encoding.
  String toPem() => certificateToPem(der);

  @override
  String toString() => 'X509Certificate(subject: $subject, issuer: $issuer)';
}
