import 'dart:isolate';
import 'dart:typed_data';

import '../crypto/public_key.dart';
import '../encoding/bytes.dart';
import 'attestation_report.dart';
import 'chain_validator.dart';
import 'key_description.dart';
import 'x509.dart';

/// Server policy for attestation checks beyond the cryptographic minimum.
class AttestationPolicy {
  /// Creates a policy. The defaults accept TEE and StrongBox keys, any app
  /// package, and unlocked bootloaders (reported as a warning).
  const AttestationPolicy({
    this.expectedPackageName,
    this.expectedSigningCertificateDigests = const {},
    this.requireLockedBootloader = false,
    this.allowedSecurityLevels = const {
      SecurityLevel.trustedEnvironment,
      SecurityLevel.strongBox,
    },
  });

  /// Restores a policy from [toJson].
  factory AttestationPolicy.fromJson(Map<String, dynamic> json) =>
      AttestationPolicy(
        expectedPackageName: json['expectedPackageName'] as String?,
        expectedSigningCertificateDigests: {
          for (final d
              in (json['expectedSigningCertificateDigests'] as List<dynamic>? ??
                  const []))
            d as String,
        },
        requireLockedBootloader:
            json['requireLockedBootloader'] as bool? ?? false,
        allowedSecurityLevels: {
          for (final l in (json['allowedSecurityLevels'] as List<dynamic>? ??
              const ['trustedEnvironment', 'strongBox']))
            SecurityLevel.values.byName(l as String),
        },
      );

  /// Package name the key must be attested for (from
  /// `attestationApplicationId`), or `null` to only report it.
  final String? expectedPackageName;

  /// Lower-case hex SHA-256 digests of acceptable app signing certificates.
  /// Empty means "report only".
  final Set<String> expectedSigningCertificateDigests;

  /// Fail (instead of warn) when the bootloader is unlocked or the verified
  /// boot state is not `Verified`.
  final bool requireLockedBootloader;

  /// Accepted key security levels. `Software` is always rejected.
  final Set<SecurityLevel> allowedSecurityLevels;

  /// Copy with changes.
  AttestationPolicy copyWith({
    String? expectedPackageName,
    bool clearExpectedPackageName = false,
    Set<String>? expectedSigningCertificateDigests,
    bool? requireLockedBootloader,
    Set<SecurityLevel>? allowedSecurityLevels,
  }) =>
      AttestationPolicy(
        expectedPackageName: clearExpectedPackageName
            ? null
            : expectedPackageName ?? this.expectedPackageName,
        expectedSigningCertificateDigests: expectedSigningCertificateDigests ??
            this.expectedSigningCertificateDigests,
        requireLockedBootloader:
            requireLockedBootloader ?? this.requireLockedBootloader,
        allowedSecurityLevels:
            allowedSecurityLevels ?? this.allowedSecurityLevels,
      );

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'expectedPackageName': expectedPackageName,
        'expectedSigningCertificateDigests':
            expectedSigningCertificateDigests.toList(),
        'requireLockedBootloader': requireLockedBootloader,
        'allowedSecurityLevels': [
          for (final l in allowedSecurityLevels) l.name,
        ],
      };
}

/// Verifies Android key attestation chains the way a server should.
///
/// This is a teaching implementation. A production server must also check
/// revocation (https://android.googleapis.com/attestation/status), keep the
/// roots up to date, and store challenges server-side.
class AttestationVerifier {
  /// Creates a verifier. [trustedRootSpkiSha256] defaults to Google's
  /// roots; [now] to the system clock.
  AttestationVerifier({
    Set<String>? trustedRootSpkiSha256,
    DateTime Function()? now,
  }) : _chainValidator = ChainValidator(
          trustedRootSpkiSha256: trustedRootSpkiSha256,
          now: now,
        );

  final ChainValidator _chainValidator;

  /// Runs [verify] on a background isolate. RSA-4096 and P-384 checks in
  /// pure Dart take noticeable time in debug builds.
  static Future<AttestationReport> verifyInIsolate({
    required List<Uint8List> chain,
    required Uint8List expectedChallenge,
    required String expectedPublicKey,
    AttestationPolicy policy = const AttestationPolicy(),
    Set<String>? trustedRootSpkiSha256,
    DateTime? now,
  }) {
    return Isolate.run(() => AttestationVerifier(
          trustedRootSpkiSha256: trustedRootSpkiSha256,
          now: now == null ? null : () => now,
        ).verify(
          chain: chain,
          expectedChallenge: expectedChallenge,
          expectedPublicKey: expectedPublicKey,
          policy: policy,
        ));
  }

  /// Verifies [chain] (DER, leaf first, as returned in
  /// `attestationCertificateChain`).
  ///
  /// [expectedChallenge] is the single-use challenge the server issued.
  /// [expectedPublicKey] is the `publicKey` string from `createKeys` in any
  /// format. Never throws; every problem becomes a failing check.
  AttestationReport verify({
    required List<Uint8List> chain,
    required Uint8List expectedChallenge,
    required String expectedPublicKey,
    AttestationPolicy policy = const AttestationPolicy(),
  }) {
    try {
      return _verify(chain, expectedChallenge, expectedPublicKey, policy);
    } catch (e) {
      return AttestationReport(
        checks: [
          AttestationCheck(
            id: AttestationCheckIds.chainParse,
            title: 'Attestation could be processed',
            status: CheckStatus.fail,
            detail: 'Unexpected error: $e',
          ),
        ],
        trustTier: TrustTier.untrusted,
        verifiedAt: DateTime.now().toUtc(),
        chain: chain,
      );
    }
  }

  AttestationReport _verify(
    List<Uint8List> chain,
    Uint8List expectedChallenge,
    String expectedPublicKey,
    AttestationPolicy policy,
  ) {
    final at = _chainValidator.now();
    final checks = <AttestationCheck>[];
    final chainResult = _chainValidator.validate(chain);
    checks.addAll(chainResult.checks);
    final certs = chainResult.certificates;
    final summaries = [
      for (var i = 0; i < certs.length; i++) CertificateSummary.of(certs[i], i),
    ];

    AttestationReport finish({int? selected, KeyDescription? kd}) {
      checks.add(const AttestationCheck(
        id: AttestationCheckIds.revocation,
        title: 'Revocation not checked',
        status: CheckStatus.warn,
        detail: 'This demo does not fetch the revocation list. A production '
            'server must check every certificate serial against '
            'https://android.googleapis.com/attestation/status.',
      ));
      final ok =
          kd != null && checks.every((c) => c.status != CheckStatus.fail);
      final tier = !ok
          ? TrustTier.untrusted
          : kd.effectiveSecurityLevel == SecurityLevel.strongBox
              ? TrustTier.strongBox
              : TrustTier.tee;
      return AttestationReport(
        checks: checks,
        trustTier: tier,
        verifiedAt: at,
        selectedCertificateIndex: selected,
        keyDescription: kd,
        certificates: summaries,
        chain: chain,
      );
    }

    if (!chainResult.parsed) return finish();

    // Walk from the root toward the leaf and take the FIRST certificate with
    // the extension. Anything below it may have been appended by whoever
    // holds the attested key, so its extension must not be trusted.
    int? selected;
    for (var i = certs.length - 1; i >= 0; i--) {
      if (certs[i].hasKeyAttestationExtension) {
        selected = i;
        break;
      }
    }
    if (selected == null) {
      checks.add(const AttestationCheck(
        id: AttestationCheckIds.extensionPresent,
        title: 'Key attestation extension found',
        status: CheckStatus.fail,
        detail: 'No certificate carries extension 1.3.6.1.4.1.11129.2.1.17.',
      ));
      return finish();
    }
    checks.add(AttestationCheck(
      id: AttestationCheckIds.extensionPresent,
      title: 'Key attestation extension found',
      status: CheckStatus.pass,
      detail: selected == 0
          ? 'In the leaf certificate (#0).'
          : 'In certificate #$selected (closest to the root).',
    ));
    if (selected > 0) {
      final extra = [
        for (var i = 0; i < selected; i++)
          '#$i${certs[i].hasKeyAttestationExtension ? ' (with its own attestation extension)' : ''}',
      ];
      checks.add(AttestationCheck(
        id: AttestationCheckIds.extensionPosition,
        title: 'Attestation certificate is the leaf',
        status: CheckStatus.fail,
        detail: 'Certificates ${extra.join(', ')} follow the attestation '
            'certificate. A genuine chain ends there; extra certificates can '
            'be minted by anyone holding the attested key (chain '
            'extension attack). Their contents were ignored.',
      ));
    }

    final attestationCert = certs[selected];
    final KeyDescription kd;
    try {
      kd = KeyDescription.fromCertificate(attestationCert)!;
    } on FormatException catch (e) {
      checks.add(AttestationCheck(
        id: AttestationCheckIds.keyDescription,
        title: 'Key description parses',
        status: CheckStatus.fail,
        detail: e.message,
      ));
      return finish(selected: selected);
    }
    final trusted = chainResult.isValid;
    checks.add(AttestationCheck(
      id: AttestationCheckIds.keyDescription,
      title: 'Key description parses',
      status: CheckStatus.pass,
      detail: '${kd.implementationName} attestation v${kd.attestationVersion}'
          '${trusted ? '' : ' — the chain is not trusted, so the values '
              'below are unverified claims'}.',
    ));
    if (kd.warnings.isNotEmpty) {
      checks.add(AttestationCheck(
        id: AttestationCheckIds.keyDescriptionEncoding,
        title: 'Key description encoding',
        status: CheckStatus.warn,
        detail: kd.warnings.join('; '),
      ));
    }

    checks
      ..add(_checkChallenge(kd, expectedChallenge))
      ..add(_checkSecurityLevel(kd, policy))
      ..add(_checkPublicKey(attestationCert, expectedPublicKey))
      ..add(_checkOrigin(kd))
      ..add(_checkBootState(kd, policy))
      ..add(_checkApplication(kd, policy))
      ..add(_userAuthInfo(kd))
      ..add(_keyPropertiesInfo(kd));
    return finish(selected: selected, kd: kd);
  }

  static AttestationCheck _checkChallenge(
      KeyDescription kd, Uint8List expected) {
    final ok = constantTimeEquals(kd.attestationChallenge, expected);
    return AttestationCheck(
      id: AttestationCheckIds.challenge,
      title: 'Challenge matches',
      status: ok ? CheckStatus.pass : CheckStatus.fail,
      detail: ok
          ? 'The attested challenge equals the ${expected.length}-byte '
              'challenge the server issued.'
          : 'The attested challenge (${kd.attestationChallenge.length} bytes) '
              'differs from the one the server issued — a replayed or '
              'foreign attestation.',
    );
  }

  static AttestationCheck _checkSecurityLevel(
      KeyDescription kd, AttestationPolicy policy) {
    final level = kd.effectiveSecurityLevel;
    final levels = 'attestation: ${kd.attestationSecurityLevel.label}, '
        'key: ${kd.keyMintSecurityLevel.label}';
    if (level == SecurityLevel.software) {
      return AttestationCheck(
        id: AttestationCheckIds.securityLevel,
        title: 'Key is in secure hardware',
        status: CheckStatus.fail,
        detail: 'Software key ($levels): no hardware protection.',
      );
    }
    if (!policy.allowedSecurityLevels.contains(level)) {
      return AttestationCheck(
        id: AttestationCheckIds.securityLevel,
        title: 'Key is in secure hardware',
        status: CheckStatus.fail,
        detail: '${level.label} is not allowed by policy ($levels).',
      );
    }
    return AttestationCheck(
      id: AttestationCheckIds.securityLevel,
      title: 'Key is in secure hardware',
      status: CheckStatus.pass,
      detail: '${level.label} ($levels).',
    );
  }

  static AttestationCheck _checkPublicKey(
      X509Certificate attestationCert, String expectedPublicKey) {
    const title = 'Attested key is the registered key';
    final attested = attestationCert.publicKey;
    if (attested is UnsupportedPublicKey) {
      return AttestationCheck(
        id: AttestationCheckIds.publicKey,
        title: title,
        status: CheckStatus.fail,
        detail: 'The attested key uses an unsupported algorithm: '
            '${attested.reason}.',
      );
    }
    final ParsedPublicKey expected;
    try {
      expected = ParsedPublicKey.parse(expectedPublicKey);
    } on FormatException catch (e) {
      return AttestationCheck(
        id: AttestationCheckIds.publicKey,
        title: title,
        status: CheckStatus.fail,
        detail: 'The registered public key could not be parsed: ${e.message}',
      );
    }
    final ok = attested.sameKeyAs(expected);
    return AttestationCheck(
      id: AttestationCheckIds.publicKey,
      title: title,
      status: ok ? CheckStatus.pass : CheckStatus.fail,
      detail: ok
          ? '${attested.description}, fingerprint '
              '${formatFingerprint(attested.fingerprint, maxGroups: 4)}.'
          : 'The certificate attests ${attested.description} '
              '${formatFingerprint(attested.fingerprint, maxGroups: 4)}, but '
              'the client registered ${expected.description} '
              '${formatFingerprint(expected.fingerprint, maxGroups: 4)}.',
    );
  }

  static AttestationCheck _checkOrigin(KeyDescription kd) {
    const title = 'Key was generated in hardware';
    final origin =
        kd.hardwareEnforced.originValue ?? kd.softwareEnforced.originValue;
    if (origin == null) {
      return const AttestationCheck(
        id: AttestationCheckIds.origin,
        title: title,
        status: CheckStatus.warn,
        detail: 'The attestation does not report the key origin.',
      );
    }
    final ok = origin == KeyOrigin.generated.value;
    final name = KeyOrigin.fromValue(origin)?.label ?? '$origin';
    return AttestationCheck(
      id: AttestationCheckIds.origin,
      title: title,
      status: ok ? CheckStatus.pass : CheckStatus.fail,
      detail: ok
          ? 'Origin: Generated.'
          : 'Origin: $name — the key material existed outside the secure '
              'hardware.',
    );
  }

  static AttestationCheck _checkBootState(
      KeyDescription kd, AttestationPolicy policy) {
    const title = 'Device boot state';
    final rot = kd.rootOfTrust;
    final soft =
        policy.requireLockedBootloader ? CheckStatus.fail : CheckStatus.warn;
    if (rot == null) {
      return AttestationCheck(
        id: AttestationCheckIds.bootState,
        title: title,
        status: soft,
        detail: 'No root of trust in the hardware-enforced list.',
      );
    }
    final summary = 'Bootloader ${rot.deviceLocked ? 'locked' : 'unlocked'}, '
        'verified boot: ${rot.verifiedBootState.label}.';
    if (rot.deviceLocked &&
        rot.verifiedBootState == VerifiedBootState.verified) {
      return AttestationCheck(
        id: AttestationCheckIds.bootState,
        title: title,
        status: CheckStatus.pass,
        detail: summary,
      );
    }
    return AttestationCheck(
      id: AttestationCheckIds.bootState,
      title: title,
      status: soft,
      detail: '$summary The key is still hardware-backed, but the OS may be '
          'modified.${policy.requireLockedBootloader ? ' Policy requires a '
              'locked, verified device.' : ''}',
    );
  }

  static AttestationCheck _checkApplication(
      KeyDescription kd, AttestationPolicy policy) {
    const title = 'Requesting app';
    final app = kd.attestationApplicationId;
    final expectedPackage = policy.expectedPackageName;
    final expectedDigests = policy.expectedSigningCertificateDigests;
    if (app == null) {
      final required = expectedPackage != null || expectedDigests.isNotEmpty;
      return AttestationCheck(
        id: AttestationCheckIds.application,
        title: title,
        status: required ? CheckStatus.fail : CheckStatus.info,
        detail: 'The attestation has no attestationApplicationId.',
      );
    }
    final names = app.packageNames;
    final digests = [for (final d in app.signatureDigests) toHex(d)];
    final described = 'Package ${names.join(', ')}; signing certificate '
        'SHA-256 ${digests.map((d) => formatFingerprint(d, maxGroups: 4)).join(', ')}.';
    final problems = <String>[
      if (expectedPackage != null && !names.contains(expectedPackage))
        'expected package $expectedPackage',
      if (expectedDigests.isNotEmpty &&
          !digests.any((d) => expectedDigests.contains(d.toLowerCase())))
        'expected an allowed signing certificate',
    ];
    if (problems.isNotEmpty) {
      return AttestationCheck(
        id: AttestationCheckIds.application,
        title: title,
        status: CheckStatus.fail,
        detail: '$described Policy ${problems.join(' and ')}.',
      );
    }
    final enforced = expectedPackage != null || expectedDigests.isNotEmpty;
    return AttestationCheck(
      id: AttestationCheckIds.application,
      title: title,
      status: enforced ? CheckStatus.pass : CheckStatus.info,
      detail: enforced
          ? described
          : '$described Not enforced by policy (the package is reported by '
              'Android, not by the secure hardware).',
    );
  }

  static AttestationCheck _userAuthInfo(KeyDescription kd) {
    final hw = kd.hardwareEnforced;
    final String summary;
    if (hw.noAuthRequired || kd.softwareEnforced.noAuthRequired) {
      summary = 'No user authentication (noAuthRequired): anyone holding the '
          'unlocked device can use this key.';
    } else {
      switch (hw.userAuthType) {
        case 2:
          summary = 'Biometric only (userAuthType 2).';
        case 3:
          summary = 'Biometric or device credential (userAuthType 3).';
        case 1:
          summary = 'Device credential only (userAuthType 1).';
        case null:
          summary = 'userAuthType is not hardware-enforced.';
        default:
          summary = 'userAuthType ${hw.userAuthType}.';
      }
    }
    final extras = <String>[
      if (hw.authTimeout != null)
        'authTimeout ${hw.authTimeout == 0x7fffffff ? 'none (per-use)' : '${hw.authTimeout}s'}',
      if (hw.trustedUserPresenceRequired) 'trustedUserPresenceRequired',
      if (hw.unlockedDeviceRequired) 'unlockedDeviceRequired',
    ];
    return AttestationCheck(
      id: AttestationCheckIds.userAuth,
      title: 'User authentication',
      status: CheckStatus.info,
      detail: extras.isEmpty ? summary : '$summary ${extras.join(', ')}.',
    );
  }

  static AttestationCheck _keyPropertiesInfo(KeyDescription kd) {
    final hw = kd.hardwareEnforced;
    final alg = hw.algorithm == null
        ? 'unknown algorithm'
        : KeyMintNames.name(KeyMintNames.algorithms, hw.algorithm!);
    final parts = <String>[
      [
        alg,
        if (hw.ecCurve != null)
          KeyMintNames.name(KeyMintNames.ecCurves, hw.ecCurve!)
        else if (hw.keySize != null)
          '${hw.keySize}',
      ].join(' '),
      if (hw.purposes != null)
        'purposes ${hw.purposes!.map((p) => KeyMintNames.name(KeyMintNames.purposes, p)).join('/')}',
      if (hw.digests != null)
        'digests ${hw.digests!.map((d) => KeyMintNames.name(KeyMintNames.digests, d)).join('/')}',
      'Android ${KeyMintNames.osVersion(hw.osVersion)}',
      'patch ${KeyMintNames.patchLevel(hw.osPatchLevel)}',
      '${kd.implementationName} ${kd.keyMintVersion}',
    ];
    return AttestationCheck(
      id: AttestationCheckIds.keyProperties,
      title: 'Key properties',
      status: CheckStatus.info,
      detail: '${parts.join(' · ')}.',
    );
  }
}
