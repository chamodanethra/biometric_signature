import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/attestation_fixtures.dart';
import 'support/fixtures.dart';

void main() {
  group('matches Google expected values', () {
    for (final path in fixturesWithJson) {
      test(path, () {
        final fixture = AttestationFixture(path);
        final kd = KeyDescription.fromCertificate(fixture.certificates.first);
        expect(kd, isNotNull);
        expect(kd!.toJson(), fixture.expected);
        expect(kd.warnings, isEmpty);
      });
    }
  });

  test('akita TEE EC: typed fields', () {
    final kd = KeyDescription.fromCertificate(
        AttestationFixture('akita/sdk34/TEE_EC_NONE').certificates.first)!;
    expect(kd.attestationVersion, 300);
    expect(kd.implementationName, 'KeyMint');
    expect(kd.attestationSecurityLevel, SecurityLevel.trustedEnvironment);
    expect(kd.effectiveSecurityLevel, SecurityLevel.trustedEnvironment);
    expect(String.fromCharCodes(kd.attestationChallenge), 'challenge');
    final hw = kd.hardwareEnforced;
    expect(hw.purposes, [2]);
    expect(hw.algorithm, 3);
    expect(hw.keySize, 256);
    expect(hw.ecCurve, 1);
    expect(hw.noAuthRequired, isTrue);
    expect(hw.origin, KeyOrigin.generated);
    expect(hw.rootOfTrust!.deviceLocked, isFalse);
    expect(hw.rootOfTrust!.verifiedBootState, VerifiedBootState.unverified);
    expect(hw.osVersion, 140000);
    expect(KeyMintNames.osVersion(hw.osVersion), '14.0.0');
    expect(KeyMintNames.patchLevel(hw.vendorPatchLevel), '2024-08-05');
    expect(kd.attestationApplicationId!.packageNames,
        ['com.google.wireless.android.security.attestationverifier.collector']);
    expect(kd.softwareEnforced.creationTime!.year, 2024);
  });

  test('user auth fields: biometric-or-credential (3) and per-use timeout', () {
    final kd = KeyDescription.fromCertificate(
        AttestationFixture('blueline/sdk28/SB_RSA_NONE_USERAUTH')
            .certificates
            .first)!;
    expect(kd.implementationName, 'Keymaster');
    expect(kd.effectiveSecurityLevel, SecurityLevel.strongBox);
    expect(kd.hardwareEnforced.userAuthType, 3);
    expect(kd.hardwareEnforced.noAuthRequired, isFalse);
    expect(kd.hardwareEnforced.authTimeout, 0x7fffffff);
    expect(kd.hardwareEnforced.trustedUserPresenceRequired, isTrue);
    expect(KeyMintNames.userAuthType(3), 'device credential or biometric (3)');
  });

  test('old attestation version 2 (walleye) parses', () {
    final kd = KeyDescription.fromCertificate(
        AttestationFixture('walleye/sdk27/TEE_EC_NONE').certificates.first)!;
    expect(kd.attestationVersion, 2);
    expect(kd.hardwareEnforced.rootOfTrust!.verifiedBootHash, isNull);
  });

  test('tags out of ascending order are rejected', () {
    final certs = X509Certificate.parsePemChain(
        fixtureText('attestation/invalid/tags_not_in_ascending_order.pem'));
    expect(
      () => KeyDescription.fromCertificate(certs.first),
      throwsA(isA<KeyDescriptionParseException>()
          .having((e) => e.message, 'message', contains('ascending order'))),
    );
  });

  test('a non-DER deviceLocked boolean is flagged, not fatal', () {
    final certs = X509Certificate.parsePemChain(
        fixtureText('attestation/invalid/malformed_rot_device_locked.pem'));
    final kd = KeyDescription.fromCertificate(certs.first)!;
    expect(kd.rootOfTrust!.deviceLocked, isTrue);
    expect(kd.rootOfTrust!.deviceLockedStrictDer, isFalse);
    expect(kd.warnings.single, contains('Non-DER'));
  });

  group('synthetic encodings', () {
    Map<String, dynamic> parseList(List<List<int>> entries) =>
        AuthorizationList.parse(DerObject.parse(DerEncoder.sequence(entries)))
            .toJson();

    test('unknown tags are skipped', () {
      final list = AuthorizationList.parse(DerObject.parse(DerEncoder.sequence([
        DerEncoder.explicit(2, DerEncoder.integerInt(3)),
        DerEncoder.explicit(999, DerEncoder.integerInt(1)),
        DerEncoder.explicit(1000, DerEncoder.nullValue()),
      ])));
      expect(list.algorithm, 3);
      expect(list.unknownTags, [999, 1000]);
    });

    test('duplicate tags are rejected', () {
      expect(
        () => parseList([
          DerEncoder.explicit(2, DerEncoder.integerInt(3)),
          DerEncoder.explicit(2, DerEncoder.integerInt(1)),
        ]),
        throwsA(isA<KeyDescriptionParseException>()),
      );
    });

    test('a malformed known tag is dropped with a warning', () {
      final list = AuthorizationList.parse(DerObject.parse(DerEncoder.sequence([
        DerEncoder.explicit(2, DerEncoder.octetString([1])),
        DerEncoder.explicit(3, DerEncoder.integerInt(256)),
      ])));
      expect(list.algorithm, isNull);
      expect(list.keySize, 256);
      expect(list.warnings.single, contains('[2]'));
    });

    test('implicitly tagged entries are rejected', () {
      expect(
        () => parseList([
          DerEncoder.tlv(
            tagClass: DerTagClass.contextSpecific,
            constructed: false,
            tagNumber: 2,
            content: [3],
          ),
        ]),
        throwsA(isA<KeyDescriptionParseException>()),
      );
    });

    test('rollbackResistance (303) and deviceUniqueAttestation (720)', () {
      final json = parseList([
        DerEncoder.explicit(303, DerEncoder.nullValue()),
        DerEncoder.explicit(720, DerEncoder.nullValue()),
      ]);
      expect(
          json, {'rollbackResistance': true, 'deviceUniqueAttestation': true});
    });
  });
}
