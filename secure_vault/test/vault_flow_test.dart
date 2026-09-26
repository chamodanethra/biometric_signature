import 'dart:convert';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/testing.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secure_vault_example/client/reveal_service.dart';
import 'package:secure_vault_example/client/vault_controller.dart';
import 'package:secure_vault_example/models/sealed_item.dart';
import 'package:secure_vault_example/models/vault_key_record.dart';

import 'support/test_device.dart';

void main() {
  restorePluginPlatformAfterEachTest();

  final cases = [
    (DevicePlatform.android, VaultKeyChoice.ec, 'ECIES (Android hybrid)'),
    (DevicePlatform.android, VaultKeyChoice.rsa, 'RSA-OAEP (Android keystore)'),
    (DevicePlatform.ios, VaultKeyChoice.ec, 'ECIES (Apple Secure Enclave)'),
    (DevicePlatform.ios, VaultKeyChoice.rsa, 'RSA-OAEP (Apple)'),
    (DevicePlatform.macos, VaultKeyChoice.ec, 'ECIES (Apple Secure Enclave)'),
  ];

  for (final (platform, choice, label) in cases) {
    group('${platform.label} ${choice.name}', () {
      test('server seals, device stores ciphertext, decrypt reveals', () async {
        final d = await TestDevice.start(platform);
        expect(d.controller.phase, VaultPhase.setup);
        final provisioned = await d.provision(choice);
        expect(d.controller.phase, VaultPhase.ready);
        expect(provisioned.scheme.label, label);

        // The scheme follows the platform and key, with exact parameters.
        switch (provisioned.scheme) {
          case EciesScheme(:final variant):
            expect(choice, VaultKeyChoice.ec);
            expect(
                variant,
                platform == DevicePlatform.android
                    ? EciesVariant.android
                    : EciesVariant.apple);
          case RsaOaepScheme(:final mgf1):
            expect(choice, VaultKeyChoice.rsa);
            expect(
                mgf1,
                platform == DevicePlatform.android
                    ? RsaOaepMgf1.sha1
                    : RsaOaepMgf1.sha256);
          case UnsupportedScheme(:final reason):
            fail('Unexpected unsupported scheme: $reason');
        }

        // createKeys was called with the vault alias and flags.
        final create = d.fake.calls.firstWhere((c) => c.method == 'createKeys');
        expect(create.keyAlias, 'vault');
        final config = create.arguments['config']! as CreateKeysConfig;
        expect(
            config.signatureType,
            choice == VaultKeyChoice.ec
                ? SignatureType.ecdsa
                : SignatureType.rsa);
        expect(config.enableDecryption, isTrue);
        expect(config.setInvalidatedByBiometricEnrollment, isTrue);
        expect(config.failIfExists, isTrue);
        expect(config.useDeviceCredentials, isFalse);
        expect(config.promptSubtitle, isNotEmpty);

        final record = d.controller.record!;
        final hybrid =
            platform == DevicePlatform.android && choice == VaultKeyChoice.ec;
        expect(record.isHybridMode, hybrid);
        expect(record.decryptingPublicKey != null, hybrid);

        // The server registered the same key the device computed.
        final devices = await d.services.server.devices();
        expect(devices.single.keyFingerprint, record.encryptionKeyFingerprint);

        final secrets = await d.services.server.secrets();
        final items = d.services.repository.items;
        expect(items, hasLength(secrets.length));
        expect(
            items.where((i) => i.format == SealFormat.envelope), hasLength(1),
            reason: 'the recovery codes exceed 190 bytes');

        for (final secret in secrets) {
          final item = d.services.repository.byId('server-${secret.id}')!;
          expect(item.recipientKey, record.encryptionKeyFingerprint);
          // Only ciphertext is stored on the device.
          expect(jsonEncode(item.toJson()), isNot(contains(secret.value)));
          for (final format in [PayloadFormat.base64, PayloadFormat.hex]) {
            final outcome = await d.controller.reveal(item, format: format);
            expect(outcome, isA<Revealed>());
            outcome as Revealed;
            expect(outcome.plaintext, secret.value);
            expect(outcome.viaEnvelope, item.format == SealFormat.envelope);
            expect(outcome.authenticationType, AuthenticationType.biometric);
          }
        }

        final decrypt = d.fake.calls.lastWhere((c) => c.method == 'decrypt');
        expect(decrypt.keyAlias, 'vault');
        expect(decrypt.arguments['payloadFormat'], PayloadFormat.hex);
        expect(decrypt.arguments['promptMessage'], contains('Reveal'));
        final decryptConfig = decrypt.arguments['config']! as DecryptConfig;
        expect(decryptConfig.promptSubtitle, isNotEmpty);
        expect(decryptConfig.cancelButtonText, 'Keep hidden');
        expect(decryptConfig.allowDeviceCredentials, isFalse);
      });

      test('notes are sealed without touching the plugin', () async {
        final d = await TestDevice.start(platform);
        await d.provision(choice);
        final callsBefore = d.fake.calls.length;

        final short = await d.controller.addNote(title: 'PIN', body: '4321');
        final longBody = '${'long note ' * 40}— ünïcødé ✓';
        final long = await d.controller.addNote(title: 'Essay', body: longBody);

        // Write-only: sealing needs only the public key.
        expect(d.fake.calls.length, callsBefore);
        expect(short.format, SealFormat.direct);
        expect(long.format, SealFormat.envelope);
        expect(long.envelope!.toJson()['ciphertext'], isNot(contains('long')));

        final a = await d.controller.reveal(short) as Revealed;
        final b = await d.controller.reveal(long) as Revealed;
        expect(a.plaintext, '4321');
        expect(b.plaintext, longBody);
        expect(b.viaEnvelope, isTrue);
      });
    });
  }

  test('useDeviceCredentials is passed to createKeys and every decrypt',
      () async {
    final d = await TestDevice.start(DevicePlatform.android);
    await d.provision(VaultKeyChoice.ec, useDeviceCredentials: true);
    final config = d.fake.calls
        .firstWhere((c) => c.method == 'createKeys')
        .arguments['config']! as CreateKeysConfig;
    expect(config.useDeviceCredentials, isTrue);
    d.fake.authenticationTypeToReport = AuthenticationType.credential;
    final item = d.services.repository.items.first;
    final outcome = await d.controller.reveal(item) as Revealed;
    expect(outcome.authenticationType, AuthenticationType.credential);
    final decryptConfig = d.fake.calls
        .lastWhere((c) => c.method == 'decrypt')
        .arguments['config']! as DecryptConfig;
    expect(decryptConfig.allowDeviceCredentials, isTrue);
  });

  test('user cancel is reported, not treated as a broken key', () async {
    final d = await TestDevice.start(DevicePlatform.ios);
    await d.provision(VaultKeyChoice.ec);
    d.fake.enqueueResult(FakeOperation.decrypt, BiometricError.userCanceled);
    final outcome =
        await d.controller.reveal(d.services.repository.items.first);
    expect(outcome, isA<RevealFailed>());
    outcome as RevealFailed;
    expect(outcome.code, BiometricError.userCanceled);
    expect(outcome.health, isNull);
    expect(d.controller.keyState, VaultKeyState.healthy);
  });

  test('Windows: the server refuses the key and decrypt is notAvailable',
      () async {
    final d = await TestDevice.start(DevicePlatform.windows);
    expect(d.controller.phase, VaultPhase.setup);
    expect(d.controller.capabilities.supportsDecrypt, isFalse);

    final outcome = await d.controller
        .provision(choice: VaultKeyChoice.ec, useDeviceCredentials: false);
    expect(outcome, isA<RegistrationFailed>());
    outcome as RegistrationFailed;
    expect(outcome.rejected, isTrue);
    expect(outcome.message, contains('notAvailable'));
    expect(d.controller.phase, VaultPhase.setup);

    // Even an item sealed for this device could not be revealed.
    final otherKey = SoftwareEcKeyPair.generate();
    final item = SealedItem.seal(
      id: 'x',
      title: 'x',
      origin: ItemOrigin.shared,
      scheme: EciesScheme(EciesVariant.apple, otherKey.spki),
      plaintext: 'secret',
      createdAt: DateTime.utc(2026),
    );
    final reveal = await d.controller.reveals.reveal(item);
    expect(reveal, isA<RevealFailed>());
    expect((reveal as RevealFailed).code, BiometricError.notAvailable);
  });

  test('preflight: no screen lock → passcodeNotSet', () async {
    final d = TestDevice(DevicePlatform.android);
    d.fake.deviceLockSet = false;
    d.use();
    await d.controller.start();
    final preflight = await d.controller.preflight();
    expect(preflight.blocker, BiometricError.passcodeNotSet);
    final outcome = await d.controller
        .provision(choice: VaultKeyChoice.ec, useDeviceCredentials: false);
    expect(outcome, isA<KeyCreationFailed>());
    expect((outcome as KeyCreationFailed).code, BiometricError.passcodeNotSet);
  });

  test('preflight: no biometrics enrolled → notEnrolled', () async {
    final d = TestDevice(DevicePlatform.ios);
    d.fake.availability = BiometricAvailability(
      canAuthenticate: false,
      hasEnrolledBiometrics: false,
      availableBiometrics: const [],
    );
    d.use();
    await d.controller.start();
    expect(
        (await d.controller.preflight()).blocker, BiometricError.notEnrolled);
  });

  test('a key that survived a reinstall: keyAlreadyExists, then register it',
      () async {
    final d = TestDevice(DevicePlatform.ios);
    d.use();
    // The keychain kept a key; the app data is gone.
    await d.services.api.createKeys(
      keyAlias: 'vault',
      config: CreateKeysConfig(signatureType: SignatureType.ecdsa),
    );
    await d.controller.start();
    expect(d.controller.phase, VaultPhase.setup);
    expect(d.controller.existingKeyOnDevice, isTrue);

    final first = await d.controller
        .provision(choice: VaultKeyChoice.ec, useDeviceCredentials: false);
    expect(first, isA<KeyCreationFailed>());
    expect((first as KeyCreationFailed).code, BiometricError.keyAlreadyExists);

    final existing = d.fake.keyFor('vault')!.signingSpki;
    final second =
        await d.controller.registerExistingKey(useDeviceCredentials: false);
    expect(second, isA<Provisioned>());
    expect(d.controller.phase, VaultPhase.ready);
    // failIfExists kept the original key.
    expect(d.fake.keyFor('vault')!.signingSpki, existing);
    final item = d.services.repository.items.first;
    expect(await d.controller.reveal(item), isA<Revealed>());
  });
}
