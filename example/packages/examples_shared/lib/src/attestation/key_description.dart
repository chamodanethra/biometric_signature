import 'dart:convert';
import 'dart:typed_data';

import '../encoding/der.dart';
import 'x509.dart';

/// The key description extension is malformed or violates the schema.
class KeyDescriptionParseException extends FormatException {
  /// Creates the exception.
  const KeyDescriptionParseException(super.message);

  @override
  String toString() => 'KeyDescriptionParseException: $message';
}

/// Where the key (or the attestation) lives.
enum SecurityLevel {
  /// Software keystore: no hardware protection.
  software(0, 'Software', 'SOFTWARE'),

  /// Trusted Execution Environment.
  trustedEnvironment(1, 'TEE', 'TRUSTED_ENVIRONMENT'),

  /// StrongBox: a separate secure element.
  strongBox(2, 'StrongBox', 'STRONG_BOX');

  const SecurityLevel(this.value, this.label, this.constantName);

  /// ASN.1 ENUMERATED value.
  final int value;

  /// Display name.
  final String label;

  /// Name used by Google's reference implementation.
  final String constantName;

  /// Looks up [value]; throws [KeyDescriptionParseException] if unknown.
  static SecurityLevel fromValue(int value) {
    for (final level in values) {
      if (level.value == value) return level;
    }
    throw KeyDescriptionParseException('Unknown security level $value');
  }
}

/// Verified boot state from the root of trust.
enum VerifiedBootState {
  /// Boot chain verified with the OEM key (locked, stock).
  verified(0, 'Verified', 'VERIFIED'),

  /// Verified with a user-installed key (custom ROM, relocked).
  selfSigned(1, 'Self-signed', 'SELF_SIGNED'),

  /// Not verified (unlocked bootloader).
  unverified(2, 'Unverified', 'UNVERIFIED'),

  /// Verification failed.
  failed(3, 'Failed', 'FAILED');

  const VerifiedBootState(this.value, this.label, this.constantName);

  /// ASN.1 ENUMERATED value.
  final int value;

  /// Display name.
  final String label;

  /// Name used by Google's reference implementation.
  final String constantName;

  /// Looks up [value]; throws [KeyDescriptionParseException] if unknown.
  static VerifiedBootState fromValue(int value) {
    for (final state in values) {
      if (state.value == value) return state;
    }
    throw KeyDescriptionParseException('Unknown verified boot state $value');
  }
}

/// How the key material came to exist.
enum KeyOrigin {
  /// Generated inside the secure hardware.
  generated(0, 'Generated', 'GENERATED'),

  /// Derived inside the secure hardware.
  derived(1, 'Derived', 'DERIVED'),

  /// Imported from outside.
  imported(2, 'Imported', 'IMPORTED'),

  /// Reserved.
  reserved(3, 'Reserved', 'RESERVED'),

  /// Securely imported (wrapped key import).
  securelyImported(4, 'Securely imported', 'SECURELY_IMPORTED');

  const KeyOrigin(this.value, this.label, this.constantName);

  /// ASN.1 INTEGER value.
  final int value;

  /// Display name.
  final String label;

  /// Name used by Google's reference implementation.
  final String constantName;

  /// Looks up [value]; `null` if unknown.
  static KeyOrigin? fromValue(int value) {
    for (final origin in values) {
      if (origin.value == value) return origin;
    }
    return null;
  }
}

/// `RootOfTrust` from the hardware-enforced list.
class RootOfTrust {
  /// Creates the value.
  const RootOfTrust({
    required this.verifiedBootKey,
    required this.deviceLocked,
    required this.verifiedBootState,
    this.verifiedBootHash,
    this.deviceLockedStrictDer = true,
  });

  /// Hash of the key that verified the boot image.
  final Uint8List verifiedBootKey;

  /// Whether the bootloader is locked.
  final bool deviceLocked;

  /// Verified boot state.
  final VerifiedBootState verifiedBootState;

  /// Digest of the verified boot data (attestation v3+).
  final Uint8List? verifiedBootHash;

  /// `false` when `deviceLocked` used a non-DER BOOLEAN encoding (e.g.
  /// 0x01 instead of 0xFF). Seen on some devices; flagged, not fatal.
  final bool deviceLockedStrictDer;
}

/// One package in `AttestationApplicationId`.
class AttestationPackageInfo {
  /// Creates the value.
  const AttestationPackageInfo(this.name, this.version);

  /// Package name.
  final String name;

  /// Version code.
  final BigInt version;
}

/// The app that requested the key (software-enforced: reported by Android,
/// not by the secure hardware).
class AttestationApplicationId {
  /// Creates the value.
  const AttestationApplicationId(this.packages, this.signatureDigests);

  /// Packages sharing the calling UID.
  final List<AttestationPackageInfo> packages;

  /// SHA-256 digests of the app signing certificates.
  final List<Uint8List> signatureDigests;

  /// Package names.
  List<String> get packageNames => [for (final p in packages) p.name];
}

/// Human-readable names for KeyMint enum values.
abstract final class KeyMintNames {
  /// `purpose` values.
  static const Map<int, String> purposes = {
    0: 'ENCRYPT',
    1: 'DECRYPT',
    2: 'SIGN',
    3: 'VERIFY',
    5: 'WRAP_KEY',
    6: 'AGREE_KEY',
    7: 'ATTEST_KEY',
  };

  /// `algorithm` values.
  static const Map<int, String> algorithms = {
    1: 'RSA',
    3: 'EC',
    4: 'ML-DSA',
    32: 'AES',
    33: '3DES',
    128: 'HMAC',
  };

  /// `digest` values.
  static const Map<int, String> digests = {
    0: 'NONE',
    1: 'MD5',
    2: 'SHA-1',
    3: 'SHA-2-224',
    4: 'SHA-2-256',
    5: 'SHA-2-384',
    6: 'SHA-2-512',
  };

  /// `padding` values.
  static const Map<int, String> paddings = {
    1: 'NONE',
    2: 'RSA_OAEP',
    3: 'RSA_PSS',
    4: 'RSA_PKCS1_1_5_ENCRYPT',
    5: 'RSA_PKCS1_1_5_SIGN',
    64: 'PKCS7',
  };

  /// `ecCurve` values.
  static const Map<int, String> ecCurves = {
    0: 'P-224',
    1: 'P-256',
    2: 'P-384',
    3: 'P-521',
    4: 'CURVE_25519',
  };

  /// `blockMode` values.
  static const Map<int, String> blockModes = {
    1: 'ECB',
    2: 'CBC',
    3: 'CTR',
    32: 'GCM',
  };

  /// Name for [value] in [table], or the number itself.
  static String name(Map<int, String> table, int value) =>
      table[value] ?? '$value';

  /// Describes a `userAuthType` bitmask (1 = password/PIN, 2 = biometric).
  static String userAuthType(int? mask) {
    if (mask == null) return 'not set';
    final parts = <String>[
      if (mask & 1 != 0) 'device credential',
      if (mask & 2 != 0) 'biometric',
    ];
    return parts.isEmpty ? 'none ($mask)' : '${parts.join(' or ')} ($mask)';
  }

  /// Formats an `osVersion` such as 140000 as `14.0.0`.
  static String osVersion(int? value) {
    if (value == null) return 'unknown';
    if (value == 0) return '0 (unset/unlocked)';
    return '${value ~/ 10000}.${(value ~/ 100) % 100}.${value % 100}';
  }

  /// Formats a patch level (YYYYMM or YYYYMMDD) as `2024-08` / `2024-08-05`.
  static String patchLevel(int? value) {
    if (value == null) return 'unknown';
    final s = '$value';
    if (s.length == 6) return '${s.substring(0, 4)}-${s.substring(4)}';
    if (s.length == 8) {
      return '${s.substring(0, 4)}-${s.substring(4, 6)}-${s.substring(6)}';
    }
    return s;
  }
}

/// KeyMint authorization tags this parser understands.
abstract final class KeyMintTag {
  /// purpose.
  static const int purpose = 1;

  /// algorithm.
  static const int algorithm = 2;

  /// keySize.
  static const int keySize = 3;

  /// blockMode.
  static const int blockMode = 4;

  /// digest.
  static const int digest = 5;

  /// padding.
  static const int padding = 6;

  /// ecCurve.
  static const int ecCurve = 10;

  /// mlDsaVariant.
  static const int mlDsaVariant = 11;

  /// rsaPublicExponent.
  static const int rsaPublicExponent = 200;

  /// rsaOaepMgfDigest.
  static const int rsaOaepMgfDigest = 203;

  /// rollbackResistance (KeyMint).
  static const int rollbackResistance = 303;

  /// earlyBootOnly.
  static const int earlyBootOnly = 305;

  /// activeDateTime.
  static const int activeDateTime = 400;

  /// originationExpireDateTime.
  static const int originationExpireDateTime = 401;

  /// usageExpireDateTime.
  static const int usageExpireDateTime = 402;

  /// usageCountLimit.
  static const int usageCountLimit = 405;

  /// noAuthRequired.
  static const int noAuthRequired = 503;

  /// userAuthType.
  static const int userAuthType = 504;

  /// authTimeout.
  static const int authTimeout = 505;

  /// allowWhileOnBody.
  static const int allowWhileOnBody = 506;

  /// trustedUserPresenceRequired.
  static const int trustedUserPresenceRequired = 507;

  /// trustedConfirmationRequired.
  static const int trustedConfirmationRequired = 508;

  /// unlockedDeviceRequired.
  static const int unlockedDeviceRequired = 509;

  /// creationDateTime.
  static const int creationDateTime = 701;

  /// origin.
  static const int origin = 702;

  /// rollbackResistant (Keymaster 3 and older).
  static const int rollbackResistant = 703;

  /// rootOfTrust.
  static const int rootOfTrust = 704;

  /// osVersion.
  static const int osVersion = 705;

  /// osPatchLevel.
  static const int osPatchLevel = 706;

  /// attestationApplicationId.
  static const int attestationApplicationId = 709;

  /// vendorPatchLevel.
  static const int vendorPatchLevel = 718;

  /// bootPatchLevel.
  static const int bootPatchLevel = 719;

  /// deviceUniqueAttestation.
  static const int deviceUniqueAttestation = 720;

  /// moduleHash.
  static const int moduleHash = 724;

  /// Device ID tags (710–717, 723) and their JSON names.
  static const Map<int, String> attestationIds = {
    710: 'attestationIdBrand',
    711: 'attestationIdDevice',
    712: 'attestationIdProduct',
    713: 'attestationIdSerial',
    714: 'attestationIdImei',
    715: 'attestationIdMeid',
    716: 'attestationIdManufacturer',
    717: 'attestationIdModel',
    723: 'attestationIdSecondImei',
  };
}

/// An `AuthorizationList` (softwareEnforced or hardwareEnforced).
///
/// Tolerant across attestation versions: unknown tags are skipped (see
/// [unknownTags]); a malformed value of a known tag is dropped with a
/// warning. Tags that are not in strictly ascending order make the whole
/// list invalid, matching Google's verifier.
class AuthorizationList {
  AuthorizationList._();

  /// An empty list.
  factory AuthorizationList.empty() => AuthorizationList._();

  /// Parses an AuthorizationList SEQUENCE.
  factory AuthorizationList.parse(DerObject sequence, {String name = 'list'}) {
    final list = AuthorizationList._();
    int? previous;
    for (final entry in sequence.asSequence()) {
      if (entry.tagClass != DerTagClass.contextSpecific || !entry.constructed) {
        throw KeyDescriptionParseException(
            '$name entries must be explicitly tagged, found '
            '${entry.tagDescription}');
      }
      final tag = entry.tagNumber;
      if (previous != null && tag <= previous) {
        throw KeyDescriptionParseException(
            'AuthorizationList tags must be in ascending order '
            '($name: [$tag] after [$previous])');
      }
      previous = tag;
      list.tags.add(tag);
      try {
        list._apply(tag, entry.explicitInner());
      } on FormatException catch (e) {
        list.warnings.add('$name [$tag] ignored: ${e.message}');
      }
    }
    return list;
  }

  /// Tag numbers in encoded order.
  final List<int> tags = [];

  /// Tags this parser does not know (skipped).
  final List<int> unknownTags = [];

  /// Non-fatal problems found while parsing.
  final List<String> warnings = [];

  /// [1] purposes.
  List<int>? purposes;

  /// [2] algorithm.
  int? algorithm;

  /// [3] key size in bits.
  int? keySize;

  /// [4] block modes.
  List<int>? blockModes;

  /// [5] digests.
  List<int>? digests;

  /// [6] paddings.
  List<int>? paddings;

  /// [10] EC curve.
  int? ecCurve;

  /// [11] ML-DSA variant.
  int? mlDsaVariant;

  /// [200] RSA public exponent.
  BigInt? rsaPublicExponent;

  /// [203] OAEP MGF digests.
  List<int>? rsaOaepMgfDigests;

  /// [303] rollbackResistance.
  bool rollbackResistance = false;

  /// [305] earlyBootOnly.
  bool earlyBootOnly = false;

  /// [400] activeDateTime (ms since epoch).
  int? activeDateTime;

  /// [401] originationExpireDateTime (ms since epoch).
  int? originationExpireDateTime;

  /// [402] usageExpireDateTime (ms since epoch).
  int? usageExpireDateTime;

  /// [405] usageCountLimit.
  int? usageCountLimit;

  /// [503] noAuthRequired: the key can be used without user authentication.
  bool noAuthRequired = false;

  /// [504] userAuthType bitmask: 1 = device credential, 2 = biometric.
  int? userAuthType;

  /// [505] authTimeout in seconds.
  int? authTimeout;

  /// [506] allowWhileOnBody.
  bool allowWhileOnBody = false;

  /// [507] trustedUserPresenceRequired.
  bool trustedUserPresenceRequired = false;

  /// [508] trustedConfirmationRequired.
  bool trustedConfirmationRequired = false;

  /// [509] unlockedDeviceRequired.
  bool unlockedDeviceRequired = false;

  /// [701] creationDateTime (ms since epoch).
  int? creationDateTime;

  /// [702] origin value.
  int? originValue;

  /// [703] rollbackResistant (old Keymaster).
  bool rollbackResistant = false;

  /// [704] root of trust.
  RootOfTrust? rootOfTrust;

  /// [705] OS version, e.g. 140000.
  int? osVersion;

  /// [706] OS patch level, YYYYMM.
  int? osPatchLevel;

  /// [709] attestation application id.
  AttestationApplicationId? attestationApplicationId;

  /// [710–717, 723] device identifiers, keyed by JSON name.
  final Map<String, String> attestationIds = {};

  /// [718] vendor patch level, YYYYMMDD.
  int? vendorPatchLevel;

  /// [719] boot patch level, YYYYMMDD.
  int? bootPatchLevel;

  /// [720] deviceUniqueAttestation.
  bool deviceUniqueAttestation = false;

  /// [724] module hash.
  Uint8List? moduleHash;

  /// [702] origin as an enum.
  KeyOrigin? get origin =>
      originValue == null ? null : KeyOrigin.fromValue(originValue!);

  /// [creationDateTime] as a UTC [DateTime].
  DateTime? get creationTime => creationDateTime == null
      ? null
      : DateTime.fromMillisecondsSinceEpoch(creationDateTime!, isUtc: true);

  /// Whether the list contains no tags.
  bool get isEmpty => tags.isEmpty;

  void _apply(int tag, DerObject value) {
    switch (tag) {
      case KeyMintTag.purpose:
        purposes = _intSet(value);
      case KeyMintTag.algorithm:
        algorithm = value.asInt();
      case KeyMintTag.keySize:
        keySize = value.asInt();
      case KeyMintTag.blockMode:
        blockModes = _intSet(value);
      case KeyMintTag.digest:
        digests = _intSet(value);
      case KeyMintTag.padding:
        paddings = _intSet(value);
      case KeyMintTag.ecCurve:
        ecCurve = value.asInt();
      case KeyMintTag.mlDsaVariant:
        mlDsaVariant = value.asInt();
      case KeyMintTag.rsaPublicExponent:
        rsaPublicExponent = value.asBigInt();
      case KeyMintTag.rsaOaepMgfDigest:
        rsaOaepMgfDigests = _intSet(value);
      case KeyMintTag.rollbackResistance:
        rollbackResistance = true;
      case KeyMintTag.earlyBootOnly:
        earlyBootOnly = true;
      case KeyMintTag.activeDateTime:
        activeDateTime = value.asInt();
      case KeyMintTag.originationExpireDateTime:
        originationExpireDateTime = value.asInt();
      case KeyMintTag.usageExpireDateTime:
        usageExpireDateTime = value.asInt();
      case KeyMintTag.usageCountLimit:
        usageCountLimit = value.asInt();
      case KeyMintTag.noAuthRequired:
        noAuthRequired = true;
      case KeyMintTag.userAuthType:
        userAuthType = value.asInt();
      case KeyMintTag.authTimeout:
        authTimeout = value.asInt();
      case KeyMintTag.allowWhileOnBody:
        allowWhileOnBody = true;
      case KeyMintTag.trustedUserPresenceRequired:
        trustedUserPresenceRequired = true;
      case KeyMintTag.trustedConfirmationRequired:
        trustedConfirmationRequired = true;
      case KeyMintTag.unlockedDeviceRequired:
        unlockedDeviceRequired = true;
      case KeyMintTag.creationDateTime:
        creationDateTime = value.asInt();
      case KeyMintTag.origin:
        originValue = value.asInt();
      case KeyMintTag.rollbackResistant:
        rollbackResistant = true;
      case KeyMintTag.rootOfTrust:
        rootOfTrust = _parseRootOfTrust(value);
        if (!rootOfTrust!.deviceLockedStrictDer) {
          warnings.add('Non-DER encoded boolean in RootOfTrust.deviceLocked');
        }
      case KeyMintTag.osVersion:
        osVersion = value.asInt();
      case KeyMintTag.osPatchLevel:
        osPatchLevel = value.asInt();
      case KeyMintTag.attestationApplicationId:
        attestationApplicationId = _parseApplicationId(value.asOctetString());
      case KeyMintTag.vendorPatchLevel:
        vendorPatchLevel = value.asInt();
      case KeyMintTag.bootPatchLevel:
        bootPatchLevel = value.asInt();
      case KeyMintTag.deviceUniqueAttestation:
        deviceUniqueAttestation = true;
      case KeyMintTag.moduleHash:
        moduleHash = Uint8List.fromList(value.asOctetString());
      default:
        final idName = KeyMintTag.attestationIds[tag];
        if (idName != null) {
          attestationIds[idName] = utf8.decode(value.asOctetString());
        } else {
          unknownTags.add(tag);
        }
    }
  }

  static List<int> _intSet(DerObject value) =>
      [for (final v in value.asSet()) v.asInt()]..sort();

  static RootOfTrust _parseRootOfTrust(DerObject value) {
    final f = value.asSequence();
    if (f.length != 3 && f.length != 4) {
      throw const KeyDescriptionParseException(
          'RootOfTrust must have 3 or 4 fields');
    }
    return RootOfTrust(
      verifiedBootKey: Uint8List.fromList(f[0].asOctetString()),
      deviceLocked: f[1].asBool(),
      deviceLockedStrictDer: f[1].isStrictDerBoolean,
      verifiedBootState: VerifiedBootState.fromValue(f[2].asEnumerated()),
      verifiedBootHash:
          f.length == 4 ? Uint8List.fromList(f[3].asOctetString()) : null,
    );
  }

  static AttestationApplicationId _parseApplicationId(Uint8List bytes) {
    final f = DerObject.parse(bytes).asSequence();
    if (f.length != 2) {
      throw const KeyDescriptionParseException(
          'AttestationApplicationId must have 2 fields');
    }
    final packages = <AttestationPackageInfo>[];
    for (final info in f[0].asSet()) {
      final p = info.asSequence();
      if (p.length != 2) {
        throw const KeyDescriptionParseException(
            'AttestationPackageInfo must have 2 fields');
      }
      packages.add(AttestationPackageInfo(
          utf8.decode(p[0].asOctetString()), p[1].asBigInt()));
    }
    final digests = [
      for (final d in f[1].asSet()) Uint8List.fromList(d.asOctetString()),
    ];
    return AttestationApplicationId(packages, digests);
  }

  /// JSON in the shape of Google's `android/keyattestation` test data:
  /// numbers as strings, bytes as base64, enums by constant name, and
  /// absent tags omitted.
  Map<String, dynamic> toJson() {
    List<String>? strings(List<int>? v) => v?.map((e) => '$e').toList();
    final rot = rootOfTrust;
    final app = attestationApplicationId;
    return {
      if (purposes != null) 'purposes': strings(purposes),
      if (algorithm != null) 'algorithms': '$algorithm',
      if (keySize != null) 'keySize': '$keySize',
      if (blockModes != null) 'blockModes': strings(blockModes),
      if (digests != null) 'digests': strings(digests),
      if (paddings != null) 'paddings': strings(paddings),
      if (ecCurve != null) 'ecCurve': '$ecCurve',
      if (mlDsaVariant != null) 'mlDsaVariant': '$mlDsaVariant',
      if (rsaPublicExponent != null) 'rsaPublicExponent': '$rsaPublicExponent',
      if (rsaOaepMgfDigests != null)
        'rsaOaepMgfDigests': strings(rsaOaepMgfDigests),
      if (rollbackResistance) 'rollbackResistance': true,
      if (earlyBootOnly) 'earlyBootOnly': true,
      if (activeDateTime != null) 'activeDateTime': '$activeDateTime',
      if (originationExpireDateTime != null)
        'originationExpireDateTime': '$originationExpireDateTime',
      if (usageExpireDateTime != null)
        'usageExpireDateTime': '$usageExpireDateTime',
      if (usageCountLimit != null) 'usageCountLimit': '$usageCountLimit',
      if (noAuthRequired) 'noAuthRequired': true,
      if (userAuthType != null) 'userAuthType': '$userAuthType',
      if (authTimeout != null) 'authTimeout': '$authTimeout',
      if (allowWhileOnBody) 'allowWhileOnBody': true,
      if (trustedUserPresenceRequired) 'trustedUserPresenceRequired': true,
      if (trustedConfirmationRequired) 'trustedConfirmationRequired': true,
      if (unlockedDeviceRequired) 'unlockedDeviceRequired': true,
      if (creationDateTime != null) 'creationDateTime': '$creationDateTime',
      if (originValue != null) 'origin': origin?.constantName ?? '$originValue',
      if (rollbackResistant) 'rollbackResistant': true,
      if (rot != null)
        'rootOfTrust': {
          'verifiedBootKey': base64.encode(rot.verifiedBootKey),
          'deviceLocked': rot.deviceLocked,
          'verifiedBootState': rot.verifiedBootState.constantName,
          if (rot.verifiedBootHash != null)
            'verifiedBootHash': base64.encode(rot.verifiedBootHash!),
        },
      if (osVersion != null) 'osVersion': '$osVersion',
      if (_validPatchLevel(osPatchLevel)) 'osPatchLevel': '$osPatchLevel',
      if (app != null)
        'attestationApplicationId': {
          'packages': [
            for (final p in app.packages)
              {'name': p.name, 'version': '${p.version}'},
          ],
          'signatures': [
            for (final s in app.signatureDigests) base64.encode(s),
          ],
        },
      ...attestationIds,
      if (_validPatchLevel(vendorPatchLevel))
        'vendorPatchLevel': '$vendorPatchLevel',
      if (_validPatchLevel(bootPatchLevel)) 'bootPatchLevel': '$bootPatchLevel',
      if (deviceUniqueAttestation) 'deviceUniqueAttestation': true,
      if (moduleHash != null) 'moduleHash': base64.encode(moduleHash!),
    };
  }

  static bool _validPatchLevel(int? value) {
    if (value == null) return false;
    final s = '$value';
    if (s.length != 6 && s.length != 8) return false;
    final month = int.parse(s.substring(4, 6));
    return month >= 1 && month <= 12;
  }
}

/// The Android key attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
class KeyDescription {
  KeyDescription._({
    required this.rawDer,
    required this.attestationVersion,
    required this.attestationSecurityLevel,
    required this.keyMintVersion,
    required this.keyMintSecurityLevel,
    required this.attestationChallenge,
    required this.uniqueId,
    required this.softwareEnforced,
    required this.hardwareEnforced,
    required this.warnings,
  });

  /// Parses the extension value (the DER inside the extnValue OCTET STRING).
  ///
  /// Throws [KeyDescriptionParseException] for malformed or out-of-order
  /// data.
  factory KeyDescription.parse(Uint8List extensionValue) {
    try {
      final f = DerObject.parse(extensionValue).asSequence();
      if (f.length < 8) {
        throw KeyDescriptionParseException(
            'KeyDescription must have 8 fields, found ${f.length}');
      }
      final software = AuthorizationList.parse(f[6], name: 'softwareEnforced');
      final hardware = AuthorizationList.parse(f[7], name: 'hardwareEnforced');
      return KeyDescription._(
        rawDer: Uint8List.fromList(extensionValue),
        attestationVersion: f[0].asInt(),
        attestationSecurityLevel: SecurityLevel.fromValue(f[1].asEnumerated()),
        keyMintVersion: f[2].asInt(),
        keyMintSecurityLevel: SecurityLevel.fromValue(f[3].asEnumerated()),
        attestationChallenge: Uint8List.fromList(f[4].asOctetString()),
        uniqueId: Uint8List.fromList(f[5].asOctetString()),
        softwareEnforced: software,
        hardwareEnforced: hardware,
        warnings: [
          if (f.length > 8) 'KeyDescription has ${f.length - 8} extra fields',
          ...software.warnings,
          ...hardware.warnings,
        ],
      );
    } on KeyDescriptionParseException {
      rethrow;
    } on FormatException catch (e) {
      throw KeyDescriptionParseException(e.message);
    } catch (e) {
      throw KeyDescriptionParseException('Malformed KeyDescription: $e');
    }
  }

  /// The key description in [certificate], or `null` if it has none.
  static KeyDescription? fromCertificate(X509Certificate certificate) {
    final ext = certificate.extension(X509Oids.keyAttestation);
    return ext == null ? null : KeyDescription.parse(ext.value);
  }

  /// The extension DER this was parsed from.
  final Uint8List rawDer;

  /// Attestation schema version (1–4, then 100, 200, 300, 400, 500).
  final int attestationVersion;

  /// Security level of the attestation itself.
  final SecurityLevel attestationSecurityLevel;

  /// Keymaster / KeyMint version.
  final int keyMintVersion;

  /// Security level of the key.
  final SecurityLevel keyMintSecurityLevel;

  /// The challenge the app passed as `attestationChallenge`.
  final Uint8List attestationChallenge;

  /// Unique ID (empty unless requested by a privileged app).
  final Uint8List uniqueId;

  /// Properties enforced by Android (software).
  final AuthorizationList softwareEnforced;

  /// Properties enforced by the TEE / StrongBox.
  final AuthorizationList hardwareEnforced;

  /// Non-fatal parse problems (e.g. a non-DER boolean).
  final List<String> warnings;

  /// The weaker of the attestation and key security levels.
  SecurityLevel get effectiveSecurityLevel =>
      attestationSecurityLevel.value <= keyMintSecurityLevel.value
          ? attestationSecurityLevel
          : keyMintSecurityLevel;

  /// `Keymaster` for versions below 100, otherwise `KeyMint`.
  String get implementationName =>
      attestationVersion >= 100 ? 'KeyMint' : 'Keymaster';

  /// The attestation application id, from either list.
  AttestationApplicationId? get attestationApplicationId =>
      softwareEnforced.attestationApplicationId ??
      hardwareEnforced.attestationApplicationId;

  /// The root of trust (hardware-enforced).
  RootOfTrust? get rootOfTrust => hardwareEnforced.rootOfTrust;

  /// JSON in the shape of Google's `android/keyattestation` test data.
  Map<String, dynamic> toJson() => {
        'attestationVersion': '$attestationVersion',
        'attestationSecurityLevel': attestationSecurityLevel.constantName,
        'keyMintVersion': '$keyMintVersion',
        'keyMintSecurityLevel': keyMintSecurityLevel.constantName,
        'attestationChallenge': base64.encode(attestationChallenge),
        'uniqueId': base64.encode(uniqueId),
        'softwareEnforced': softwareEnforced.toJson(),
        'hardwareEnforced': hardwareEnforced.toJson(),
      };
}
