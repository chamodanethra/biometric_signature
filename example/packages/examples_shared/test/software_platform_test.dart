import 'dart:convert';
import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/biometric_signature_platform_interface.dart'
    show BiometricSignaturePlatform;
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/testing.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late SoftwareBiometricPlatform fake;
  final api = BiometricSignature();

  SoftwareBiometricPlatform install(DevicePlatform platform) {
    fake = SoftwareBiometricPlatform(simulatedPlatform: platform);
    BiometricSignaturePlatform.instance = fake;
    return fake;
  }

  group('sign → verify', () {
    for (final platform in [
      DevicePlatform.android,
      DevicePlatform.ios,
      DevicePlatform.macos,
      DevicePlatform.windows,
    ]) {
      for (final type in SignatureType.values) {
        test('${platform.label} ${type.name}', () async {
          install(platform);
          final created = await api.createKeys(
            keyAlias: 'k',
            config: CreateKeysConfig(signatureType: type),
            keyFormat: KeyFormat.pem,
          );
          expect(created.code, BiometricError.success);
          final expectRsa =
              platform == DevicePlatform.windows || type == SignatureType.rsa;
          expect(created.algorithm, expectRsa ? 'RSA' : 'EC');
          expect(created.publicKey, startsWith('-----BEGIN PUBLIC KEY-----'));

          final bytes = utf8.encode('canonical payload');
          final sig =
              await api.createSignatureFromBytes(payload: bytes, keyAlias: 'k');
          expect(sig.code, BiometricError.success);
          expect(
            verifySignature(
              publicKey: created.publicKey!,
              message: bytes,
              signature: base64.decode(sig.signature!),
            ).isValid,
            isTrue,
          );
          final text = await api.createSignature(
              payload: 'hello',
              keyAlias: 'k',
              signatureFormat: SignatureFormat.hex);
          expect(
            verifySignature(
              publicKey: text.publicKey!,
              message: utf8.encode('hello'),
              signature: fromHex(text.signature!),
            ).isValid,
            isTrue,
          );
          expect(text.signatureBytes, fromHex(text.signature!));
        });
      }
    }
  });

  group('encrypt with EncryptionTarget → fake decrypt', () {
    Future<void> roundTrip(DevicePlatform platform, CreateKeysConfig config,
        {required Type expectedScheme}) async {
      install(platform);
      final created = await api.createKeys(keyAlias: 'v', config: config);
      expect(created.code, BiometricError.success);
      final scheme = EncryptionTarget.resolve(
        platform: platform,
        algorithm: created.algorithm,
        publicKey: created.publicKey,
        decryptingPublicKey: created.decryptingPublicKey,
        decryptingAlgorithm: created.decryptingAlgorithm,
        isHybridMode: created.isHybridMode,
      );
      expect(scheme.runtimeType, expectedScheme, reason: scheme.description);
      for (final format in PayloadFormat.values) {
        final ct = scheme.encrypt('secret ✓ ${format.name}');
        final payload =
            format == PayloadFormat.hex ? toHex(ct) : base64.encode(ct);
        final result = await api.decrypt(
            payload: payload, payloadFormat: format, keyAlias: 'v');
        expect(result.code, BiometricError.success, reason: result.error);
        expect(result.decryptedData, 'secret ✓ ${format.name}');
      }
      // getKeyInfo resolves to the same scheme.
      final info = await api.getKeyInfo(keyAlias: 'v');
      final again = EncryptionTarget.resolve(
        platform: platform,
        algorithm: info.algorithm,
        publicKey: info.publicKey,
        decryptingPublicKey: info.decryptingPublicKey,
        isHybridMode: info.isHybridMode,
      );
      expect(again.toJson(), scheme.toJson());
    }

    test('Android hybrid EC (ECIES, Android KDF)', () async {
      await roundTrip(
        DevicePlatform.android,
        CreateKeysConfig(
            signatureType: SignatureType.ecdsa, enableDecryption: true),
        expectedScheme: EciesScheme,
      );
      final info = await api.getKeyInfo(keyAlias: 'v');
      expect(info.isHybridMode, isTrue);
      expect(info.decryptingPublicKey, isNot(info.publicKey));
    });

    test('Android RSA with enableDecryption (OAEP, MGF1-SHA-1)', () async {
      await roundTrip(
        DevicePlatform.android,
        CreateKeysConfig(
            signatureType: SignatureType.rsa, enableDecryption: true),
        expectedScheme: RsaOaepScheme,
      );
    });

    test('Apple EC (ECIES, Apple KDF)', () async {
      await roundTrip(
        DevicePlatform.ios,
        CreateKeysConfig(signatureType: SignatureType.ecdsa),
        expectedScheme: EciesScheme,
      );
    });

    test('Apple RSA (OAEP, MGF1-SHA-256; publicKey, not hybrid)', () async {
      await roundTrip(
        DevicePlatform.macos,
        CreateKeysConfig(signatureType: SignatureType.rsa),
        expectedScheme: RsaOaepScheme,
      );
      final info = await api.getKeyInfo(keyAlias: 'v');
      expect(info.isHybridMode, isFalse);
      expect(info.decryptingPublicKey, isNull);
    });

    test('a payload for the wrong platform fails to decrypt', () async {
      install(DevicePlatform.ios);
      final created = await api.createKeys(
          config: CreateKeysConfig(signatureType: SignatureType.ecdsa));
      final wrong = EciesScheme(
          EciesVariant.android, publicKeyToSpki(created.publicKey!));
      final result = await api.decrypt(
          payload: wrong.encryptToBase64('x'),
          payloadFormat: PayloadFormat.base64);
      expect(result.code, BiometricError.unknown);
    });

    test('Windows decrypt is notAvailable; Android signing-only EC fails',
        () async {
      install(DevicePlatform.windows);
      await api.createKeys();
      expect(
          (await api.decrypt(
                  payload: 'AA==', payloadFormat: PayloadFormat.base64))
              .code,
          BiometricError.notAvailable);
      install(DevicePlatform.android);
      final ec = await api.createKeys(
          config: CreateKeysConfig(signatureType: SignatureType.ecdsa));
      expect(
          EncryptionTarget.resolve(
                  platform: DevicePlatform.android,
                  algorithm: ec.algorithm,
                  publicKey: ec.publicKey,
                  isHybridMode: ec.isHybridMode)
              .isSupported,
          isFalse);
      expect(
          (await api.decrypt(
                  payload: 'AA==', payloadFormat: PayloadFormat.base64))
              .code,
          BiometricError.unknown);
    });
  });

  group('key lifecycle', () {
    test('failIfExists keeps the existing key', () async {
      install(DevicePlatform.android);
      final first = await api.createKeys(keyAlias: 'a');
      final second = await api.createKeys(
          keyAlias: 'a', config: CreateKeysConfig(failIfExists: true));
      expect(second.code, BiometricError.keyAlreadyExists);
      expect((await api.getKeyInfo(keyAlias: 'a')).publicKey, first.publicKey);
      final replaced = await api.createKeys(keyAlias: 'a');
      expect(replaced.publicKey, isNot(first.publicKey));
    });

    test('invalidate → keyInvalidated, isValid false', () async {
      install(DevicePlatform.android);
      await api.createKeys(keyAlias: 'bio');
      expect(fake.invalidate(alias: 'bio'), isTrue);
      final sig = await api.createSignature(payload: 'x', keyAlias: 'bio');
      expect(sig.code, BiometricError.keyInvalidated);
      expect(guidanceFor(sig.code).action, RecoveryAction.recreateKey);
      final health = await probeKey(api, alias: 'bio');
      expect(health.status, KeyHealthStatus.invalidated);
      expect((await api.getKeyInfo(keyAlias: 'bio')).isValid, isNull);
    });

    test('enrollment change spares silent and device-credential Apple keys',
        () async {
      install(DevicePlatform.ios);
      await api.createKeys(keyAlias: 'bio');
      await api.createKeys(
          keyAlias: 'silent',
          config: CreateKeysConfig(requireAuthentication: false));
      await api.createKeys(
          keyAlias: 'pin',
          config: CreateKeysConfig(useDeviceCredentials: true));
      await api.createKeys(
          keyAlias: 'any',
          config: CreateKeysConfig(setInvalidatedByBiometricEnrollment: false));
      fake.simulateBiometricEnrollmentChange();
      expect(fake.keyFor('bio')!.invalidated, isTrue);
      expect(fake.keyFor('silent')!.invalidated, isFalse);
      expect(fake.keyFor('pin')!.invalidated, isFalse);
      expect(fake.keyFor('any')!.invalidated, isFalse);
    });

    test('missing keys and deletion', () async {
      install(DevicePlatform.android);
      expect((await api.createSignature(payload: 'x', keyAlias: 'none')).code,
          BiometricError.keyNotFound);
      expect(
          (await api.decrypt(
                  payload: 'AA==',
                  payloadFormat: PayloadFormat.base64,
                  keyAlias: 'none'))
              .code,
          BiometricError.keyNotFound);
      await api.createKeys(keyAlias: 'a');
      await api.createKeys(keyAlias: 'b');
      await api.createKeys();
      expect(fake.aliases, containsAll(['a', 'b', null]));
      expect(await api.deleteKeys(keyAlias: 'a'), isTrue);
      expect(await api.biometricKeyExists(keyAlias: 'a'), isFalse);
      expect(await api.biometricKeyExists(keyAlias: 'b'), isTrue);
      expect(await api.deleteAllKeys(), isTrue);
      expect(fake.aliases, isEmpty);
      expect((await probeKey(api)).status, KeyHealthStatus.missing);
    });

    test('silent keys report unknown; prompted keys report the configured type',
        () async {
      install(DevicePlatform.android).authenticationTypeToReport =
          AuthenticationType.credential;
      await api.createKeys(
          keyAlias: 'silent',
          config: CreateKeysConfig(requireAuthentication: false));
      await api.createKeys(keyAlias: 'bio');
      expect(
          (await api.createSignature(payload: 'x', keyAlias: 'silent'))
              .authenticationType,
          AuthenticationType.unknown);
      expect(
          (await api.createSignature(payload: 'x', keyAlias: 'bio'))
              .authenticationType,
          AuthenticationType.credential);
    });

    test('scripted errors are returned in order, then normal results',
        () async {
      install(DevicePlatform.android);
      await api.createKeys();
      fake
        ..enqueueResult(FakeOperation.sign, BiometricError.lockedOut)
        ..enqueueResult(FakeOperation.sign, BiometricError.userCanceled);
      expect((await api.createSignature(payload: 'x')).code,
          BiometricError.lockedOut);
      expect(
          (await api.createSignatureFromBytes(payload: utf8.encode('x'))).code,
          BiometricError.userCanceled);
      expect((await api.createSignature(payload: 'x')).code,
          BiometricError.success);
      fake.enqueueResult(
          FakeOperation.simplePrompt, BiometricError.lockedOutPermanent);
      final prompt = await api.simplePrompt(promptMessage: 'Unlock');
      expect(prompt.success, isFalse);
      expect(prompt.code, BiometricError.lockedOutPermanent);
      expect((await api.simplePrompt(promptMessage: 'Unlock')).success, isTrue);
    });

    test('no screen lock → passcodeNotSet; invalid inputs', () async {
      install(DevicePlatform.ios).deviceLockSet = false;
      expect(await api.isDeviceLockSet(), isFalse);
      expect((await api.createKeys()).code, BiometricError.passcodeNotSet);
      fake.deviceLockSet = true;
      await api.createKeys();
      expect((await api.createSignature(payload: '')).code,
          BiometricError.invalidInput);
      expect(
          (await api.decrypt(payload: 'zz', payloadFormat: PayloadFormat.hex))
              .code,
          BiometricError.invalidInput);
    });

    test('empty and blank payloads match each platform', () async {
      Future<BiometricError?> sign(String payload) async =>
          (await api.createSignature(payload: payload)).code;
      Future<BiometricError?> decrypt(String payload) async => (await api
              .decrypt(payload: payload, payloadFormat: PayloadFormat.base64))
          .code;

      install(DevicePlatform.android);
      await api.createKeys(
          config: CreateKeysConfig(
              signatureType: SignatureType.ecdsa, enableDecryption: true));
      expect(await sign(''), BiometricError.invalidInput);
      expect(await sign('  '), BiometricError.invalidInput);
      expect(await decrypt('  '), BiometricError.invalidInput);

      for (final platform in [DevicePlatform.ios, DevicePlatform.macos]) {
        install(platform);
        await api.createKeys(
            config: CreateKeysConfig(signatureType: SignatureType.ecdsa));
        expect(await sign(''), BiometricError.invalidInput);
        expect(await sign('  '), BiometricError.success);
        expect(await decrypt('  '), BiometricError.invalidInput);
      }

      install(DevicePlatform.windows);
      await api.createKeys();
      expect(await sign(''), BiometricError.invalidInput);
      expect(await sign('  '), BiometricError.success);
      expect(await decrypt(''), BiometricError.notAvailable);
    });

    test('publicKeyBytes differ per platform; publicKey is always SPKI',
        () async {
      install(DevicePlatform.ios);
      final apple = await api.createKeys(
          config: CreateKeysConfig(signatureType: SignatureType.ecdsa),
          keyFormat: KeyFormat.raw);
      expect(apple.publicKeyBytes, hasLength(65));
      expect(publicKeyToSpki(apple.publicKey!), hasLength(91));
      install(DevicePlatform.android);
      final android = await api.createKeys(
          config: CreateKeysConfig(signatureType: SignatureType.ecdsa),
          keyFormat: KeyFormat.hex);
      expect(android.publicKeyBytes, hasLength(91));
      expect(fromHex(android.publicKey!), android.publicKeyBytes);
    });

    test('records calls with their arguments', () async {
      install(DevicePlatform.android);
      await api.createKeys(
          keyAlias: 'x', config: CreateKeysConfig(promptSubtitle: 'Sub'));
      final call = fake.calls.single;
      expect(call.method, 'createKeys');
      expect(call.keyAlias, 'x');
      expect((call.arguments['config'] as CreateKeysConfig?)?.promptSubtitle,
          'Sub');
    });
  });

  group('attestation', () {
    test('Android: synthetic chain verifies when its root is trusted',
        () async {
      install(DevicePlatform.android).attestedPackageName = 'com.example.demo';
      final challenge = secureRandomBytes(32);
      final created = await api.createKeys(
        keyAlias: 'att',
        config: CreateKeysConfig(
          signatureType: SignatureType.ecdsa,
          attestationChallenge: challenge,
        ),
      );
      expect(created.code, BiometricError.success);
      final chain = created.attestationCertificateChain!;
      final report = AttestationVerifier(
        trustedRootSpkiSha256: {fake.syntheticRootSpkiSha256},
      ).verify(
        chain: chain,
        expectedChallenge: challenge,
        expectedPublicKey: created.publicKey!,
        policy:
            const AttestationPolicy(expectedPackageName: 'com.example.demo'),
      );
      expect(report.passed, isTrue, reason: report.failures.join('\n'));
      expect(report.attestsBiometricOnly, isTrue);
      // Not trusted by default, like an emulator.
      expect(
          AttestationVerifier()
              .verify(
                chain: chain,
                expectedChallenge: challenge,
                expectedPublicKey: created.publicKey!,
              )
              .passed,
          isFalse);
      // getKeyInfo returns the stored chain (upload retry).
      expect(
          (await api.getKeyInfo(keyAlias: 'att')).attestationCertificateChain,
          chain);
    });

    test('Android: silent keys attest noAuthRequired', () async {
      install(DevicePlatform.android);
      final challenge = secureRandomBytes(16);
      final created = await api.createKeys(
        config: CreateKeysConfig(
          requireAuthentication: false,
          attestationChallenge: challenge,
        ),
      );
      final report = AttestationVerifier(
        trustedRootSpkiSha256: {fake.syntheticRootSpkiSha256},
      ).verify(
        chain: created.attestationCertificateChain!,
        expectedChallenge: challenge,
        expectedPublicKey: created.publicKey!,
      );
      expect(report.keyDescription!.hardwareEnforced.noAuthRequired, isTrue);
      expect(report.attestsBiometricOnly, isFalse);
    });

    test('challenge length and platform checks', () async {
      install(DevicePlatform.android);
      expect(
          (await api.createKeys(
                  config:
                      CreateKeysConfig(attestationChallenge: Uint8List(129))))
              .code,
          BiometricError.invalidInput);
      expect(
          (await api.createKeys(
                  config: CreateKeysConfig(attestationChallenge: Uint8List(0))))
              .code,
          BiometricError.invalidInput);
      fake.attestationMode = FakeAttestationMode.notSupported;
      expect(
          (await api.createKeys(
                  config: CreateKeysConfig(attestationChallenge: Uint8List(8))))
              .code,
          BiometricError.notSupported);
      for (final p in [DevicePlatform.ios, DevicePlatform.windows]) {
        install(p);
        await api.createKeys(keyAlias: 'keep');
        final r = await api.createKeys(
            keyAlias: 'keep',
            config: CreateKeysConfig(attestationChallenge: Uint8List(8)));
        expect(r.code, BiometricError.notSupported);
        expect(await api.biometricKeyExists(keyAlias: 'keep'), isTrue);
      }
    });

    test('a canned chain is returned as-is', () async {
      install(DevicePlatform.android).cannedAttestationChain = [
        Uint8List.fromList([1, 2, 3]),
      ];
      final created = await api.createKeys(
          config: CreateKeysConfig(attestationChallenge: Uint8List(4)));
      expect(created.attestationCertificateChain, [
        [1, 2, 3],
      ]);
    });
  });
}
