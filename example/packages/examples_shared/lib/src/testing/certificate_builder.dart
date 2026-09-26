import 'dart:typed_data';

import '../attestation/x509.dart';
import '../crypto/hash.dart';
import '../crypto/public_key.dart';
import '../crypto/signature_verifier.dart';
import '../crypto/software_keys.dart';
import '../encoding/der.dart';

/// Something that can sign a TBSCertificate.
abstract class CertificateSigner {
  /// The signer's SubjectPublicKeyInfo DER.
  Uint8List get spki;

  /// The signature AlgorithmIdentifier DER.
  Uint8List get algorithmIdentifier;

  /// Signs [tbs].
  Uint8List sign(Uint8List tbs);

  /// A signer backed by a software EC key (ecdsa-with-SHA256 for P-256,
  /// SHA-384 for P-384).
  factory CertificateSigner.ec(SoftwareEcKeyPair key) = _EcSigner;

  /// A signer backed by a software RSA key (sha256WithRSAEncryption).
  factory CertificateSigner.rsa(SoftwareRsaKeyPair key) = _RsaSigner;
}

class _EcSigner implements CertificateSigner {
  _EcSigner(this.key);

  final SoftwareEcKeyPair key;

  SignatureAlgorithm get _alg => key.curve == EcCurve.p384
      ? SignatureAlgorithm.ecdsaSha384
      : SignatureAlgorithm.ecdsaSha256;

  @override
  Uint8List get spki => key.spki;

  @override
  Uint8List get algorithmIdentifier =>
      DerEncoder.sequence([DerEncoder.oid(_alg.oid)]);

  @override
  Uint8List sign(Uint8List tbs) => key.sign(tbs, hash: _alg.hash);
}

class _RsaSigner implements CertificateSigner {
  _RsaSigner(this.key);

  final SoftwareRsaKeyPair key;

  @override
  Uint8List get spki => key.spki;

  @override
  Uint8List get algorithmIdentifier => DerEncoder.sequence([
        DerEncoder.oid(SignatureAlgorithm.rsaPkcs1Sha256.oid),
        DerEncoder.nullValue(),
      ]);

  @override
  Uint8List sign(Uint8List tbs) => key.sign(tbs, hash: HashAlgorithm.sha256);
}

/// Encodes an X.501 Name from attributes (one attribute per RDN).
Uint8List encodeName(List<DnAttribute> attributes) => DerEncoder.sequence([
      for (final a in attributes)
        DerEncoder.setOf([
          DerEncoder.sequence([
            DerEncoder.oid(a.oid),
            a.oid == '2.5.4.5' || a.oid == '2.5.4.6'
                ? DerEncoder.printableString(a.value)
                : DerEncoder.utf8String(a.value),
          ]),
        ]),
    ]);

/// Builds a signed X.509 v3 certificate. For tests and synthetic chains.
///
/// [signatureAlgorithmOverride] replaces the AlgorithmIdentifier (and the
/// signature is then garbage) to simulate unsupported algorithms.
Uint8List buildCertificate({
  required List<DnAttribute> subject,
  required List<DnAttribute> issuer,
  required Uint8List subjectPublicKeySpki,
  required CertificateSigner signer,
  BigInt? serialNumber,
  DateTime? notBefore,
  DateTime? notAfter,
  bool isCa = false,
  Map<String, Uint8List> extensions = const {},
  String? signatureAlgorithmOverride,
}) {
  final algId = signatureAlgorithmOverride == null
      ? signer.algorithmIdentifier
      : DerEncoder.sequence([DerEncoder.oid(signatureAlgorithmOverride)]);
  final exts = <Uint8List>[
    if (isCa)
      DerEncoder.sequence([
        DerEncoder.oid(X509Oids.basicConstraints),
        DerEncoder.boolean(true),
        DerEncoder.octetString(DerEncoder.sequence([DerEncoder.boolean(true)])),
      ]),
    for (final e in extensions.entries)
      DerEncoder.sequence([
        DerEncoder.oid(e.key),
        DerEncoder.octetString(e.value),
      ]),
  ];
  final tbs = DerEncoder.sequence([
    DerEncoder.explicit(0, DerEncoder.integerInt(2)),
    DerEncoder.integer(serialNumber ?? BigInt.one),
    algId,
    encodeName(issuer),
    DerEncoder.sequence([
      DerEncoder.time(notBefore ?? DateTime.utc(2020)),
      DerEncoder.time(notAfter ?? DateTime.utc(2099)),
    ]),
    encodeName(subject),
    subjectPublicKeySpki,
    if (exts.isNotEmpty) DerEncoder.explicit(3, DerEncoder.sequence(exts)),
  ]);
  final signature = signatureAlgorithmOverride == null
      ? signer.sign(tbs)
      : Uint8List.fromList(List.filled(64, 0x42));
  return DerEncoder.sequence([
    tbs,
    algId,
    DerEncoder.bitString(signature),
  ]);
}
