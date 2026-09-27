import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secure_vault_example/client/reveal_service.dart';
import 'package:secure_vault_example/client/vault_controller.dart';
import 'package:secure_vault_example/models/sealed_item.dart';
import 'package:secure_vault_example/models/vault_key_record.dart';
import 'package:secure_vault_example/server/in_transit_tamper.dart';
import 'package:secure_vault_example/server/provisioning_server.dart';

import 'support/test_device.dart';

void main() {
  restorePluginPlatformAfterEachTest();

  for (final (platform, choice) in [
    (DevicePlatform.android, VaultKeyChoice.ec),
    (DevicePlatform.ios, VaultKeyChoice.rsa),
  ]) {
    test(
        '${platform.label} ${choice.name}: ciphertext tampered in transit '
        'fails to decrypt; the key stays healthy', () async {
      final d = await TestDevice.start(platform);
      await d.provision(choice);

      d.services.tamper.arm(TamperTarget.devicePayload);
      final sync = await d.controller.syncServerItems();
      expect(sync.ok, isTrue);
      expect(d.services.tamper.armed, isNull);
      expect(d.services.tamper.lastEvent, contains('Office Wi-Fi password'));

      final item = d.services.repository.byId('server-wifi')!;
      // The wire log shows what the device actually received.
      final entry = d.services.transport.log.entries.last;
      expect(entry.route, ProvisioningServer.syncRoute);
      final delivered = (entry.response!['items'] as List).first as Map;
      expect(delivered['ciphertext'], item.ciphertext);

      final outcome = await d.controller.reveal(item);
      expect(outcome, isA<RevealFailed>());
      outcome as RevealFailed;
      // The flipped bit is in the first byte. For ECIES that is the ephemeral
      // key's 0x04 prefix, which the plugin rejects before any prompt; RSA-OAEP
      // ciphertext is only rejected by decryption itself.
      expect(
          outcome.code,
          choice == VaultKeyChoice.ec
              ? BiometricError.invalidInput
              : BiometricError.unknown);
      expect(outcome.ciphertextRejected, isTrue);
      expect(outcome.keyUnusable, isFalse);
      expect(d.controller.keyState, VaultKeyState.healthy);

      // Other items are unaffected, and a fresh sync repairs this one.
      final token = d.services.repository.byId('server-api-token')!;
      expect(await d.controller.reveal(token), isA<Revealed>());
      expect((await d.controller.syncServerItems()).ok, isTrue);
      final repaired = d.services.repository.byId('server-wifi')!;
      expect(await d.controller.reveal(repaired), isA<Revealed>());
    });
  }

  test('envelope content tampered: decrypt succeeds, AES-GCM rejects',
      () async {
    final d = await TestDevice.start(DevicePlatform.android);
    await d.provision(VaultKeyChoice.rsa);
    d.services.tamper.arm(TamperTarget.envelopeContent);
    await d.controller.syncServerItems();
    expect(d.services.tamper.lastEvent, contains('Account recovery codes'));

    final item = d.services.repository.byId('server-recovery-codes')!;
    expect(item.format, SealFormat.envelope);
    final decrypts = d.callCount('decrypt');
    final outcome = await d.controller.reveal(item);
    expect(outcome, isA<RevealIntegrityFailure>());
    // The biometric decrypt of the data key did happen.
    expect(d.callCount('decrypt'), decrypts + 1);
    expect((outcome as RevealIntegrityFailure).authenticationType,
        AuthenticationType.biometric);
  });

  test(
      'failed registration keeps the key; retry re-reads it without a '
      'new createKeys', () async {
    final d = await TestDevice.start(DevicePlatform.android);
    d.services.transport.failNext(ProvisioningServer.registerRoute);

    final first = await d.controller
        .provision(choice: VaultKeyChoice.ec, useDeviceCredentials: false);
    expect(first, isA<RegistrationFailed>());
    expect((first as RegistrationFailed).rejected, isFalse);
    expect(d.controller.phase, VaultPhase.setup);
    expect(d.controller.existingKeyOnDevice, isTrue);
    expect(await d.services.server.devices(), isEmpty);

    final creates = d.callCount('createKeys');
    final retry =
        await d.controller.registerExistingKey(useDeviceCredentials: false);
    expect(retry, isA<Provisioned>());
    expect(d.callCount('createKeys'), creates);
    expect(d.controller.phase, VaultPhase.ready);
    expect(d.controller.record!.isHybridMode, isTrue);
    expect(d.services.repository.items, isNotEmpty);
  });

  test('a failed sync after registration is reported, then recovers', () async {
    final d = await TestDevice.start(DevicePlatform.ios);
    d.services.transport.failNext(ProvisioningServer.syncRoute);
    final outcome = await d.controller
        .provision(choice: VaultKeyChoice.ec, useDeviceCredentials: false);
    expect(outcome, isA<Provisioned>());
    expect((outcome as Provisioned).syncError, isNotNull);
    expect(d.services.repository.items, isEmpty);
    final sync = await d.controller.syncServerItems();
    expect(sync.received, 3);
  });

  test('server secrets added later arrive on the next sync', () async {
    final d = await TestDevice.start(DevicePlatform.android);
    await d.provision(VaultKeyChoice.ec);
    await d.services.server.addSecret('Door code', '1234#');
    expect((await d.controller.syncServerItems()).received, 4);
    final item =
        d.services.repository.items.firstWhere((i) => i.title == 'Door code');
    expect((await d.controller.reveal(item) as Revealed).plaintext, '1234#');
  });

  test('reset demo deletes every key and both sides\' data', () async {
    final d = await TestDevice.start(DevicePlatform.ios);
    await d.provision(VaultKeyChoice.ec);
    await d.controller.addNote(title: 'n', body: 'b');
    final oldDeviceId = d.services.repository.deviceId;

    await d.controller.resetDemo();
    expect(d.callCount('deleteAllKeys'), 1);
    expect(d.fake.keyFor('vault'), isNull);
    expect(d.controller.phase, VaultPhase.setup);
    expect(d.services.repository.items, isEmpty);
    expect(d.controller.record, isNull);
    expect(d.services.repository.deviceId, isNot(oldDeviceId));
    expect(await d.services.server.devices(), isEmpty);
    expect(await d.services.server.secrets(), hasLength(3));
    expect(d.services.transport.log.entries, isEmpty);
  });
}
