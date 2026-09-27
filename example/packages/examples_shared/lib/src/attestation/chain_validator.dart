import 'dart:typed_data';

import '../crypto/signature_verifier.dart';
import '../encoding/bytes.dart';
import 'attestation_report.dart';
import 'google_roots.dart';
import 'software_roots.dart';
import 'x509.dart';

/// How the attestation key was provisioned, inferred from the certificate
/// directly below the root (as Google's verifier does).
enum ProvisioningMethod {
  /// Factory-provisioned attestation key (subject has `serialNumber`).
  factoryProvisioned('Factory provisioned'),

  /// Remote key provisioning (`CN=Droid CA2, O=Google LLC`).
  remotelyProvisioned('Remotely provisioned'),

  /// Unknown.
  unknown('Unknown');

  const ProvisioningMethod(this.label);

  /// Display name.
  final String label;
}

/// Which kind of root terminates the chain.
enum ChainRootKind {
  /// One of the trusted roots.
  trusted,

  /// The Android software attestation root (emulator / no secure hardware).
  androidSoftware,

  /// Anything else.
  unknown,
}

/// Result of [ChainValidator.validate].
class ChainValidationResult {
  /// Creates a result.
  const ChainValidationResult({
    required this.certificates,
    required this.checks,
    required this.rootKind,
    required this.provisioningMethod,
    this.rootSpkiSha256,
  });

  /// Certificates that parsed, leaf first. Empty if any failed to parse.
  final List<X509Certificate> certificates;

  /// One check each for parsing, links, validity and the root.
  final List<AttestationCheck> checks;

  /// The terminating root's kind.
  final ChainRootKind rootKind;

  /// Inferred provisioning method.
  final ProvisioningMethod provisioningMethod;

  /// SHA-256 of the root's SubjectPublicKeyInfo, hex.
  final String? rootSpkiSha256;

  /// Whether every certificate parsed.
  bool get parsed => certificates.isNotEmpty;

  /// Whether no check failed.
  bool get isValid =>
      parsed && checks.every((c) => c.status != CheckStatus.fail);
}

/// Validates an Android key attestation certificate chain.
///
/// For each link `i` the issuer name of certificate `i` must equal the
/// subject name of certificate `i+1`, and certificate `i` must be signed by
/// certificate `i+1`'s key. The last certificate must be self-signed, and
/// its **public key** must be trusted (matched by SPKI SHA-256, because the
/// RSA root was re-issued with the same key).
///
/// Validity periods are checked for intermediates only. Like Google's
/// verifier, the leaf's validity is ignored (it is set on the device and
/// may be skewed), the root is trusted by key, and expired intermediates of
/// factory-provisioned chains are a warning because those keys cannot be
/// rotated.
class ChainValidator {
  /// Creates a validator. [trustedRootSpkiSha256] defaults to Google's
  /// roots; [now] to the system clock.
  ChainValidator({
    Set<String>? trustedRootSpkiSha256,
    DateTime Function()? now,
  })  : trustedRootSpkiSha256 = trustedRootSpkiSha256 ?? googleRootSpkiSha256,
        now = now ?? _systemNow;

  static DateTime _systemNow() => DateTime.now().toUtc();

  /// Trusted root key fingerprints (hex SHA-256 of SPKI DER).
  final Set<String> trustedRootSpkiSha256;

  /// Clock used for validity checks.
  final DateTime Function() now;

  /// Validates [chain] (DER, leaf first — the plugin's
  /// `attestationCertificateChain`).
  ChainValidationResult validate(List<Uint8List> chain) {
    final checks = <AttestationCheck>[];
    if (chain.length < 2) {
      checks.add(AttestationCheck(
        id: AttestationCheckIds.chainParse,
        title: 'Certificate chain parses',
        status: CheckStatus.fail,
        detail: chain.isEmpty
            ? 'The chain is empty.'
            : 'Only one certificate: a chain needs at least the attestation '
                'certificate and a root.',
      ));
      return ChainValidationResult(
        certificates: const [],
        checks: checks,
        rootKind: ChainRootKind.unknown,
        provisioningMethod: ProvisioningMethod.unknown,
      );
    }

    final certs = <X509Certificate>[];
    for (var i = 0; i < chain.length; i++) {
      try {
        certs.add(X509Certificate.parse(chain[i]));
      } on FormatException catch (e) {
        checks.add(AttestationCheck(
          id: AttestationCheckIds.chainParse,
          title: 'Certificate chain parses',
          status: CheckStatus.fail,
          detail: 'Certificate #$i could not be parsed: ${e.message}',
        ));
        return ChainValidationResult(
          certificates: const [],
          checks: checks,
          rootKind: ChainRootKind.unknown,
          provisioningMethod: ProvisioningMethod.unknown,
        );
      }
    }
    final provisioning = _provisioningMethod(certs);
    checks.add(AttestationCheck(
      id: AttestationCheckIds.chainParse,
      title: 'Certificate chain parses',
      status: CheckStatus.pass,
      detail: '${certs.length} certificates (${provisioning.label}).',
    ));

    checks.add(_checkLinks(certs));
    checks.add(_checkValidity(certs, provisioning));

    final root = certs.last;
    final rootHash = toHex(root.spkiSha256);
    final ChainRootKind kind;
    final AttestationCheck rootCheck;
    if (trustedRootSpkiSha256.contains(rootHash)) {
      kind = ChainRootKind.trusted;
      final name = _googleRootName(rootHash);
      rootCheck = AttestationCheck(
        id: AttestationCheckIds.chainRoot,
        title: 'Root key is trusted',
        status: CheckStatus.pass,
        detail: name == null
            ? 'Root key $rootHash is in the configured trust set.'
            : 'Google attestation root: $name.',
      );
    } else if (androidSoftwareRootSpkiSha256.contains(rootHash)) {
      kind = ChainRootKind.androidSoftware;
      rootCheck = const AttestationCheck(
        id: AttestationCheckIds.chainRoot,
        title: 'Root key is trusted',
        status: CheckStatus.fail,
        detail: 'Untrusted root: the Android software attestation root. The '
            'key was attested by a software keystore (emulator or a device '
            'without secure hardware).',
      );
    } else {
      kind = ChainRootKind.unknown;
      rootCheck = AttestationCheck(
        id: AttestationCheckIds.chainRoot,
        title: 'Root key is trusted',
        status: CheckStatus.fail,
        detail: 'Untrusted root (${root.subject}, key $rootHash) — e.g. '
            'emulator/software attestation or a self-made chain.',
      );
    }
    checks.add(rootCheck);

    return ChainValidationResult(
      certificates: List.unmodifiable(certs),
      checks: checks,
      rootKind: kind,
      provisioningMethod: provisioning,
      rootSpkiSha256: rootHash,
    );
  }

  AttestationCheck _checkLinks(List<X509Certificate> certs) {
    const title = 'Each certificate is signed by the next';
    AttestationCheck fail(String detail) => AttestationCheck(
          id: AttestationCheckIds.chainLinks,
          title: title,
          status: CheckStatus.fail,
          detail: detail,
        );

    for (var i = 0; i < certs.length; i++) {
      final cert = certs[i];
      final isRoot = i == certs.length - 1;
      final issuer = isRoot ? cert : certs[i + 1];
      final label = isRoot ? 'root #$i' : '#$i → #${i + 1}';
      if (!cert.isIssuedBy(issuer)) {
        return fail(isRoot
            ? 'The last certificate is not self-issued (issuer '
                '"${cert.issuer}" ≠ subject "${cert.subject}"); the chain is '
                'incomplete.'
            : 'Certificate #$i issuer "${cert.issuer}" does not match '
                'certificate #${i + 1} subject "${issuer.subject}".');
      }
      if (!cert.signatureAlgorithmsMatch) {
        return fail('Certificate #$i: inner and outer signature algorithms '
            'differ.');
      }
      final outcome = cert.verifySignedBy(issuer.publicKey);
      switch (outcome) {
        case VerifyValid():
          break;
        case VerifyInvalid(:final reason):
          return fail('Signature check failed for $label '
              '(${cert.signatureAlgorithmName}): $reason');
        case VerifyUnsupported(:final reason):
          return fail('Cannot verify $label: $reason');
      }
    }
    final algs = {for (final c in certs) c.signatureAlgorithmName}.join(', ');
    return AttestationCheck(
      id: AttestationCheckIds.chainLinks,
      title: title,
      status: CheckStatus.pass,
      detail: '${certs.length - 1} links and the root self-signature verify '
          '($algs).',
    );
  }

  AttestationCheck _checkValidity(
      List<X509Certificate> certs, ProvisioningMethod provisioning) {
    const title = 'Intermediates are within their validity period';
    final at = now();
    final warnings = <String>[];
    for (var i = 1; i < certs.length - 1; i++) {
      final cert = certs[i];
      if (at.isBefore(cert.notBefore)) {
        return AttestationCheck(
          id: AttestationCheckIds.chainValidity,
          title: title,
          status: CheckStatus.fail,
          detail: 'Certificate #$i is not valid until '
              '${cert.notBefore.toIso8601String()} (clock: '
              '${at.toIso8601String()}).',
        );
      }
      if (at.isAfter(cert.notAfter)) {
        if (provisioning == ProvisioningMethod.factoryProvisioned) {
          warnings.add('#$i expired ${cert.notAfter.toIso8601String()} '
              '(tolerated for factory-provisioned keys, which cannot be '
              'rotated)');
          continue;
        }
        return AttestationCheck(
          id: AttestationCheckIds.chainValidity,
          title: title,
          status: CheckStatus.fail,
          detail: 'Certificate #$i expired on '
              '${cert.notAfter.toIso8601String()} (clock: '
              '${at.toIso8601String()}).',
        );
      }
    }
    if (warnings.isNotEmpty) {
      return AttestationCheck(
        id: AttestationCheckIds.chainValidity,
        title: title,
        status: CheckStatus.warn,
        detail: 'Expired: ${warnings.join('; ')}.',
      );
    }
    return AttestationCheck(
      id: AttestationCheckIds.chainValidity,
      title: title,
      status: CheckStatus.pass,
      detail: 'Checked at ${at.toIso8601String()}. The leaf validity is '
          'ignored (set on the device) and the root is trusted by key.',
    );
  }

  static ProvisioningMethod _provisioningMethod(List<X509Certificate> certs) {
    if (certs.length < 2) return ProvisioningMethod.unknown;
    final belowRoot = certs[certs.length - 2].subject;
    if (belowRoot.serialNumber != null) {
      return ProvisioningMethod.factoryProvisioned;
    }
    if (belowRoot.commonName == 'Droid CA2' &&
        belowRoot.organization == 'Google LLC') {
      return ProvisioningMethod.remotelyProvisioned;
    }
    return ProvisioningMethod.unknown;
  }

  static String? _googleRootName(String spkiSha256) {
    for (final root in googleAttestationRoots) {
      if (root.spkiSha256 == spkiSha256) return root.name;
    }
    return null;
  }
}
