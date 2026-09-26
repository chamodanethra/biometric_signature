import 'dart:convert';
import 'dart:typed_data';

import '../encoding/bytes.dart';
import '../encoding/pem.dart';
import 'key_description.dart';
import 'x509.dart';

/// Outcome of one verification step.
enum CheckStatus {
  /// The requirement is met.
  pass,

  /// The requirement is not met; the attestation must be rejected.
  fail,

  /// Acceptable, but worth attention (or a policy decision).
  warn,

  /// Informational.
  info,
}

/// One step of an attestation (or chain) verification.
class AttestationCheck {
  /// Creates a check.
  const AttestationCheck({
    required this.id,
    required this.title,
    required this.status,
    required this.detail,
  });

  /// Restores a check from [toJson].
  factory AttestationCheck.fromJson(Map<String, dynamic> json) =>
      AttestationCheck(
        id: json['id'] as String,
        title: json['title'] as String,
        status: CheckStatus.values.byName(json['status'] as String),
        detail: json['detail'] as String,
      );

  /// Stable identifier (see [AttestationCheckIds]).
  final String id;

  /// Short title.
  final String title;

  /// Result.
  final CheckStatus status;

  /// Explanation with the concrete values involved.
  final String detail;

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'id': id,
        'title': title,
        'status': status.name,
        'detail': detail,
      };

  @override
  String toString() => '[${status.name}] $title: $detail';
}

/// Identifiers of the checks an [AttestationReport] can contain.
abstract final class AttestationCheckIds {
  /// Every certificate parses.
  static const String chainParse = 'chain.parse';

  /// Issuer/subject names chain and every signature verifies.
  static const String chainLinks = 'chain.links';

  /// Intermediate certificates are within their validity period.
  static const String chainValidity = 'chain.validity';

  /// The root key is a trusted Google attestation root.
  static const String chainRoot = 'chain.root';

  /// A certificate carries the key attestation extension.
  static const String extensionPresent = 'attestation.extension';

  /// No certificates follow the attestation certificate.
  static const String extensionPosition = 'attestation.position';

  /// The key description parses.
  static const String keyDescription = 'attestation.keyDescription';

  /// Non-fatal encoding issues in the key description.
  static const String keyDescriptionEncoding = 'attestation.encoding';

  /// The attested challenge equals the issued one.
  static const String challenge = 'attestation.challenge';

  /// TEE or StrongBox.
  static const String securityLevel = 'attestation.securityLevel';

  /// The attested key equals the registered public key.
  static const String publicKey = 'attestation.publicKey';

  /// Key generated inside the secure hardware.
  static const String origin = 'attestation.origin';

  /// Verified boot / bootloader lock state.
  static const String bootState = 'policy.bootState';

  /// Expected app package / signing certificate.
  static const String application = 'policy.application';

  /// User-authentication requirements of the key.
  static const String userAuth = 'info.userAuth';

  /// Algorithm, purposes, OS and patch level.
  static const String keyProperties = 'info.keyProperties';

  /// Revocation status was not checked.
  static const String revocation = 'server.revocation';

  /// No attestation was provided (e.g. iOS or Windows).
  static const String notProvided = 'attestation.notProvided';
}

/// How much the server can trust the key's storage.
enum TrustTier {
  /// Verified StrongBox (secure element) key.
  strongBox('StrongBox'),

  /// Verified TEE key.
  tee('TEE'),

  /// An attestation was provided but failed verification.
  untrusted('Untrusted'),

  /// No attestation was provided.
  none('Not attested');

  const TrustTier(this.label);

  /// Display name.
  final String label;
}

/// A display-friendly summary of one chain certificate.
class CertificateSummary {
  /// Creates a summary.
  const CertificateSummary({
    required this.index,
    required this.subject,
    required this.issuer,
    required this.signatureAlgorithm,
    required this.publicKey,
    required this.notBefore,
    required this.notAfter,
    required this.sha256Fingerprint,
    required this.hasKeyAttestationExtension,
  });

  /// Summarizes [certificate] at chain position [index] (0 = leaf).
  factory CertificateSummary.of(X509Certificate certificate, int index) =>
      CertificateSummary(
        index: index,
        subject: '${certificate.subject}',
        issuer: '${certificate.issuer}',
        signatureAlgorithm: certificate.signatureAlgorithmName,
        publicKey: certificate.publicKey.description,
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
        sha256Fingerprint: toHex(certificate.sha256Fingerprint),
        hasKeyAttestationExtension: certificate.hasKeyAttestationExtension,
      );

  /// Restores a summary from [toJson].
  factory CertificateSummary.fromJson(Map<String, dynamic> json) =>
      CertificateSummary(
        index: json['index'] as int,
        subject: json['subject'] as String,
        issuer: json['issuer'] as String,
        signatureAlgorithm: json['signatureAlgorithm'] as String,
        publicKey: json['publicKey'] as String,
        notBefore: DateTime.parse(json['notBefore'] as String),
        notAfter: DateTime.parse(json['notAfter'] as String),
        sha256Fingerprint: json['sha256Fingerprint'] as String,
        hasKeyAttestationExtension: json['hasKeyAttestationExtension'] as bool,
      );

  /// Position in the chain (0 = leaf).
  final int index;

  /// Subject DN.
  final String subject;

  /// Issuer DN.
  final String issuer;

  /// Signature algorithm name.
  final String signatureAlgorithm;

  /// Public key description.
  final String publicKey;

  /// Validity start.
  final DateTime notBefore;

  /// Validity end.
  final DateTime notAfter;

  /// SHA-256 of the certificate DER, hex.
  final String sha256Fingerprint;

  /// Whether it carries the key attestation extension.
  final bool hasKeyAttestationExtension;

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'index': index,
        'subject': subject,
        'issuer': issuer,
        'signatureAlgorithm': signatureAlgorithm,
        'publicKey': publicKey,
        'notBefore': notBefore.toUtc().toIso8601String(),
        'notAfter': notAfter.toUtc().toIso8601String(),
        'sha256Fingerprint': sha256Fingerprint,
        'hasKeyAttestationExtension': hasKeyAttestationExtension,
      };
}

/// The result of verifying an Android key attestation chain.
class AttestationReport {
  /// Creates a report.
  AttestationReport({
    required List<AttestationCheck> checks,
    required this.trustTier,
    required this.verifiedAt,
    this.selectedCertificateIndex,
    this.keyDescription,
    List<CertificateSummary> certificates = const [],
    List<Uint8List> chain = const [],
  })  : checks = List.unmodifiable(checks),
        certificates = List.unmodifiable(certificates),
        chain = List.unmodifiable(chain);

  /// A report for a device that provided no attestation (iOS, macOS,
  /// Windows, or an Android device whose keystore cannot attest).
  factory AttestationReport.notProvided(String reason, {DateTime? at}) =>
      AttestationReport(
        checks: [
          AttestationCheck(
            id: AttestationCheckIds.notProvided,
            title: 'No key attestation',
            status: CheckStatus.info,
            detail: reason,
          ),
        ],
        trustTier: TrustTier.none,
        verifiedAt: at ?? DateTime.now().toUtc(),
      );

  /// Restores a report from [toJson]. The key description is re-parsed from
  /// its stored DER.
  factory AttestationReport.fromJson(Map<String, dynamic> json) {
    final kd = json['keyDescription'] as String?;
    return AttestationReport(
      checks: [
        for (final c in json['checks'] as List<dynamic>)
          AttestationCheck.fromJson(c as Map<String, dynamic>),
      ],
      trustTier: TrustTier.values.byName(json['trustTier'] as String),
      verifiedAt: DateTime.parse(json['verifiedAt'] as String),
      selectedCertificateIndex: json['selectedCertificateIndex'] as int?,
      keyDescription:
          kd == null ? null : KeyDescription.parse(base64.decode(kd)),
      certificates: [
        for (final c in (json['certificates'] as List<dynamic>? ?? const []))
          CertificateSummary.fromJson(c as Map<String, dynamic>),
      ],
      chain: [
        for (final c in (json['chain'] as List<dynamic>? ?? const []))
          base64.decode(c as String),
      ],
    );
  }

  /// Every check, in evaluation order.
  final List<AttestationCheck> checks;

  /// Overall trust tier.
  final TrustTier trustTier;

  /// When the verification ran (the verifier's clock).
  final DateTime verifiedAt;

  /// Index of the certificate whose extension was used (0 = leaf).
  final int? selectedCertificateIndex;

  /// The parsed key description, if one was found and parsed.
  final KeyDescription? keyDescription;

  /// Summaries of the chain certificates that parsed, leaf first.
  final List<CertificateSummary> certificates;

  /// The chain DER as received, leaf first.
  final List<Uint8List> chain;

  /// `true` when a key description was verified and no check failed.
  bool get passed =>
      keyDescription != null &&
      checks.isNotEmpty &&
      checks.every((c) => c.status != CheckStatus.fail);

  /// Failing checks.
  List<AttestationCheck> get failures => [
        for (final c in checks)
          if (c.status == CheckStatus.fail) c
      ];

  /// Warnings.
  List<AttestationCheck> get warnings => [
        for (final c in checks)
          if (c.status == CheckStatus.warn) c
      ];

  /// The check with [id], if present.
  AttestationCheck? check(String id) {
    for (final c in checks) {
      if (c.id == id) return c;
    }
    return null;
  }

  /// Whether the attestation proves a biometric-only key: hardware-enforced
  /// `userAuthType == 2` (biometric) and no `noAuthRequired`. Only
  /// meaningful when [passed].
  bool get attestsBiometricOnly {
    final hw = keyDescription?.hardwareEnforced;
    return passed &&
        hw != null &&
        hw.userAuthType == 2 &&
        !hw.noAuthRequired &&
        !(keyDescription!.softwareEnforced.noAuthRequired);
  }

  /// The chain as concatenated PEM (leaf first).
  String get chainPem => certificateChainToPem(chain);

  /// JSON form (bytes as base64), suitable for a mock server's storage.
  Map<String, dynamic> toJson() => {
        'checks': [for (final c in checks) c.toJson()],
        'trustTier': trustTier.name,
        'verifiedAt': verifiedAt.toUtc().toIso8601String(),
        'selectedCertificateIndex': selectedCertificateIndex,
        'keyDescription': keyDescription == null
            ? null
            : base64.encode(keyDescription!.rawDer),
        'certificates': [for (final c in certificates) c.toJson()],
        'chain': [for (final c in chain) base64.encode(c)],
      };
}
