import 'dart:convert';
import 'dart:typed_data';

import '../attestation/key_description.dart';
import '../attestation/x509.dart';
import '../crypto/public_key.dart';
import '../crypto/software_keys.dart';
import '../encoding/bytes.dart';
import '../encoding/der.dart';
import 'certificate_builder.dart';

/// Properties to embed in a synthetic key attestation.
class SyntheticKeyProperties {
  /// Creates properties. Defaults describe a TEE EC P-256 signing key that
  /// requires biometric authentication on a locked, verified device.
  const SyntheticKeyProperties({
    this.securityLevel = SecurityLevel.trustedEnvironment,
    this.noAuthRequired = false,
    this.userAuthType = 2,
    this.packageName = 'com.example.app',
    this.signingCertificateDigest,
    this.deviceLocked = true,
    this.verifiedBootState = VerifiedBootState.verified,
    this.origin = KeyOrigin.generated,
    this.osVersion = 150000,
    this.osPatchLevel = 202601,
    this.creationTime,
  });

  /// Attestation and key security level.
  final SecurityLevel securityLevel;

  /// Adds `noAuthRequired` (a silent key) instead of `userAuthType`.
  final bool noAuthRequired;

  /// `userAuthType` bitmask (1 = credential, 2 = biometric). Ignored when
  /// [noAuthRequired].
  final int userAuthType;

  /// Package in `attestationApplicationId`.
  final String packageName;

  /// SHA-256 of the app signing certificate (defaults to a fixed value).
  final Uint8List? signingCertificateDigest;

  /// Root of trust: bootloader locked.
  final bool deviceLocked;

  /// Root of trust: verified boot state.
  final VerifiedBootState verifiedBootState;

  /// Key origin.
  final KeyOrigin origin;

  /// OS version, e.g. 150000.
  final int osVersion;

  /// OS patch level, YYYYMM.
  final int osPatchLevel;

  /// Creation time (defaults to now).
  final DateTime? creationTime;
}

/// Encodes a KeyDescription extension value. Entries of each list must be
/// `[tag] EXPLICIT` values in ascending tag order (see [authorizationEntry]).
Uint8List encodeKeyDescription({
  int attestationVersion = 300,
  SecurityLevel attestationSecurityLevel = SecurityLevel.trustedEnvironment,
  int keyMintVersion = 300,
  SecurityLevel keyMintSecurityLevel = SecurityLevel.trustedEnvironment,
  required List<int> challenge,
  List<int> uniqueId = const [],
  List<Uint8List> softwareEnforced = const [],
  List<Uint8List> hardwareEnforced = const [],
}) =>
    DerEncoder.sequence([
      DerEncoder.integerInt(attestationVersion),
      DerEncoder.enumerated(attestationSecurityLevel.value),
      DerEncoder.integerInt(keyMintVersion),
      DerEncoder.enumerated(keyMintSecurityLevel.value),
      DerEncoder.octetString(challenge),
      DerEncoder.octetString(uniqueId),
      DerEncoder.sequence(softwareEnforced),
      DerEncoder.sequence(hardwareEnforced),
    ]);

/// One AuthorizationList entry: `[tag] EXPLICIT value`.
Uint8List authorizationEntry(int tag, Uint8List value) =>
    DerEncoder.explicit(tag, value);

/// Builds Android-style attestation chains signed by a synthetic root.
///
/// The chains have the real structure (root → intermediate → leaf with the
/// KeyDescription extension), so the verifier exercises every check. They
/// are **not** trusted by default: pass [rootSpkiSha256] in
/// `trustedRootSpkiSha256` in tests that want them to verify.
class SyntheticAttestation {
  /// Creates a builder. Keys default to fixed, deterministic values so
  /// [defaultRootSpkiSha256] is stable across runs.
  SyntheticAttestation(
      {SoftwareEcKeyPair? rootKey, SoftwareEcKeyPair? intermediateKey})
      : rootKey =
            rootKey ?? _deterministicKey('examples_shared synthetic root'),
        intermediateKey = intermediateKey ??
            _deterministicKey('examples_shared synthetic intermediate');

  /// The root's SPKI SHA-256 for the default keys.
  static String get defaultRootSpkiSha256 => toHex(
      _deterministicKey('examples_shared synthetic root').publicKey.spkiSha256);

  static SoftwareEcKeyPair _deterministicKey(String label) {
    final n = EcCurve.p256.domain.n;
    final d =
        bytesToBigInt(sha256Bytes(utf8.encode(label))) % (n - BigInt.one) +
            BigInt.one;
    return SoftwareEcKeyPair.fromPrivateScalar(EcCurve.p256, d);
  }

  /// Root signing key.
  final SoftwareEcKeyPair rootKey;

  /// Intermediate signing key.
  final SoftwareEcKeyPair intermediateKey;

  static const _rootName = [
    DnAttribute('2.5.4.10', 'examples_shared (synthetic, not Google)'),
    DnAttribute('2.5.4.3', 'Synthetic Attestation Root'),
  ];
  static const _intermediateName = [
    DnAttribute('2.5.4.10', 'TEE'),
    DnAttribute('2.5.4.3', 'Synthetic Attestation Key'),
  ];

  /// SHA-256 of the root SPKI, hex.
  String get rootSpkiSha256 => toHex(rootKey.publicKey.spkiSha256);

  late final Uint8List _root = buildCertificate(
    subject: _rootName,
    issuer: _rootName,
    subjectPublicKeySpki: rootKey.spki,
    signer: CertificateSigner.ec(rootKey),
    isCa: true,
  );

  late final Uint8List _intermediate = buildCertificate(
    subject: _intermediateName,
    issuer: _rootName,
    subjectPublicKeySpki: intermediateKey.spki,
    signer: CertificateSigner.ec(rootKey),
    serialNumber: BigInt.two,
    isCa: true,
  );

  /// A leaf-first chain attesting [attestedSpki] with [challenge].
  List<Uint8List> chainFor({
    required Uint8List attestedSpki,
    required List<int> challenge,
    SyntheticKeyProperties properties = const SyntheticKeyProperties(),
  }) {
    final key = ParsedPublicKey.fromSpki(attestedSpki);
    final extension = encodeKeyDescription(
      attestationSecurityLevel: properties.securityLevel,
      keyMintSecurityLevel: properties.securityLevel,
      challenge: challenge,
      softwareEnforced: [
        authorizationEntry(
          KeyMintTag.creationDateTime,
          DerEncoder.integerInt((properties.creationTime ?? DateTime.now())
              .millisecondsSinceEpoch),
        ),
        authorizationEntry(
          KeyMintTag.attestationApplicationId,
          DerEncoder.octetString(DerEncoder.sequence([
            DerEncoder.setOf([
              DerEncoder.sequence([
                DerEncoder.octetString(utf8.encode(properties.packageName)),
                DerEncoder.integerInt(1),
              ]),
            ]),
            DerEncoder.setOf([
              DerEncoder.octetString(properties.signingCertificateDigest ??
                  sha256Bytes(utf8.encode('synthetic signing certificate'))),
            ]),
          ])),
        ),
      ],
      hardwareEnforced: _hardwareList(key, properties),
    );
    final leaf = buildCertificate(
      subject: const [DnAttribute('2.5.4.3', 'Android Keystore Key')],
      issuer: _intermediateName,
      subjectPublicKeySpki: attestedSpki,
      signer: CertificateSigner.ec(intermediateKey),
      notBefore: DateTime.utc(1970),
      notAfter: DateTime.utc(2048),
      extensions: {X509Oids.keyAttestation: extension},
    );
    return [leaf, _intermediate, _root];
  }

  static List<Uint8List> _hardwareList(
      ParsedPublicKey key, SyntheticKeyProperties p) {
    final isEc = key is EcPublicKeyInfo;
    return [
      authorizationEntry(
          KeyMintTag.purpose, DerEncoder.setOf([DerEncoder.integerInt(2)])),
      authorizationEntry(
          KeyMintTag.algorithm, DerEncoder.integerInt(isEc ? 3 : 1)),
      authorizationEntry(
          KeyMintTag.keySize, DerEncoder.integerInt(key.keySizeBits)),
      authorizationEntry(
          KeyMintTag.digest, DerEncoder.setOf([DerEncoder.integerInt(4)])),
      if (!isEc)
        authorizationEntry(
            KeyMintTag.padding, DerEncoder.setOf([DerEncoder.integerInt(5)])),
      if (isEc)
        authorizationEntry(KeyMintTag.ecCurve, DerEncoder.integerInt(1)),
      if (key is RsaPublicKeyInfo)
        authorizationEntry(
            KeyMintTag.rsaPublicExponent, DerEncoder.integer(key.exponent)),
      if (p.noAuthRequired)
        authorizationEntry(KeyMintTag.noAuthRequired, DerEncoder.nullValue()),
      if (!p.noAuthRequired) ...[
        authorizationEntry(
            KeyMintTag.userAuthType, DerEncoder.integerInt(p.userAuthType)),
        authorizationEntry(
            KeyMintTag.authTimeout, DerEncoder.integerInt(0x7fffffff)),
      ],
      authorizationEntry(
          KeyMintTag.origin, DerEncoder.integerInt(p.origin.value)),
      authorizationEntry(
        KeyMintTag.rootOfTrust,
        DerEncoder.sequence([
          DerEncoder.octetString(Uint8List(32)),
          DerEncoder.boolean(p.deviceLocked),
          DerEncoder.enumerated(p.verifiedBootState.value),
          DerEncoder.octetString(Uint8List(32)),
        ]),
      ),
      authorizationEntry(
          KeyMintTag.osVersion, DerEncoder.integerInt(p.osVersion)),
      authorizationEntry(
          KeyMintTag.osPatchLevel, DerEncoder.integerInt(p.osPatchLevel)),
    ];
  }
}
