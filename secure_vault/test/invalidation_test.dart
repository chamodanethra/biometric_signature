import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secure_vault_example/client/reveal_service.dart';
import 'package:secure_vault_example/client/sharing.dart';
import 'package:secure_vault_example/client/vault_controller.dart';
import 'package:secure_vault_example/models/sealed_item.dart';
import 'package:secure_vault_example/models/vault_key_record.dart';
import 'package:secure_vault_example/server/provisioning_server.dart';

import 'support/test_device.dart';

void main() {
  restorePluginPlatformAfterEachTest();

  for (final (platform, choice) in [
    (DevicePlatform.android, VaultKeyChoice.ec),
    (DevicePlatform.android, VaultKeyChoice.rsa),
    (DevicePlatform.ios, VaultKeyChoice.ec),
    (DevicePlatform.ios, VaultKeyChoice.rsa),
  ]) {
    test(
        '${platform.label} ${choice.name}: new biometric enrollment shreds '
        'device notes; re-provisioning restores server secrets', () async {
      final d = await TestDevice.start(platform);
      await d.provision(choice);
      final note = await d.controller
          .addNote(title: 'Diary', body: 'This exists only on this device.');
      final address = await d.controller.myAddress();
      final shared = await d.controller.importShared(sealForRecipient(address,
          title: 'From a friend', secret: 'hello', from: 'friend'));
      final oldFingerprint = d.controller.record!.encryptionKeyFingerprint;

      d.fake.simulateBiometricEnrollmentChange();

      final wifi = d.services.repository.byId('server-wifi')!;
      final failed = await d.controller.reveal(wifi);
      expect(failed, isA<RevealFailed>());
      failed as RevealFailed;
      expect(failed.code, BiometricError.keyInvalidated);
      expect(failed.keyUnusable, isTrue);
      expect(d.controller.keyState, VaultKeyState.invalidated);
      expect(d.controller.accessFor(wifi), ItemAccess.awaitingReseal);
      expect(d.controller.accessFor(note), ItemAccess.lost);
      expect(d.controller.accessFor(shared), ItemAccess.lost);

      // A relaunch reaches the same conclusion via getKeyInfo(checkValidity).
      final health = await d.controller.refreshKeyHealth();
      expect(health.status, KeyHealthStatus.invalidated);
      expect(await d.controller.keys.existsAndValid(), isFalse);

      final outcome = await d.controller.reprovision();
      expect(outcome, isA<Provisioned>());
      expect((outcome as Provisioned).generation, 2);
      expect(d.controller.keyState, VaultKeyState.healthy);
      final record = d.controller.record!;
      expect(record.choice, choice);
      expect(record.encryptionKeyFingerprint, isNot(oldFingerprint));
      expect(d.fake.calls.where((c) => c.method == 'deleteKeys'), isNotEmpty);

      // The server re-sealed its secrets to the new key.
      final fresh = d.services.repository.byId('server-wifi')!;
      expect(fresh.recipientKey, record.encryptionKeyFingerprint);
      final revealed = await d.controller.reveal(fresh);
      expect(revealed, isA<Revealed>());
      expect((revealed as Revealed).plaintext, 'violet-harbor-42-lantern');
      expect(d.services.server.audit.entries.map((e) => e.event),
          contains('vault.reprovisioned'));

      // Device-only items stay sealed to the old key forever.
      expect(d.controller.accessFor(note), ItemAccess.lost);
      expect(d.controller.lostItems.map((i) => i.id),
          unorderedEquals([note.id, shared.id]));
      final attempt = await d.controller.reveal(note);
      expect(attempt, isNot(isA<Revealed>()));
      expect(await d.controller.deleteLostItems(), 2);
      expect(d.services.repository.byId(note.id), isNull);
      expect(d.controller.lostItems, isEmpty);
    });
  }

  test('iOS: a passcode-accepting key survives an enrollment change', () async {
    final d = await TestDevice.start(DevicePlatform.ios);
    await d.provision(VaultKeyChoice.ec, useDeviceCredentials: true);
    d.fake.simulateBiometricEnrollmentChange();
    final item = d.services.repository.items.first;
    expect(await d.controller.reveal(item), isA<Revealed>());
    expect(d.controller.keyState, VaultKeyState.healthy);
  });

  test('a key deleted behind the app’s back: keyNotFound → missing', () async {
    final d = await TestDevice.start(DevicePlatform.android);
    await d.provision(VaultKeyChoice.ec);
    await d.fake.deleteKeys('vault');

    final outcome =
        await d.controller.reveal(d.services.repository.items.first);
    expect(outcome, isA<RevealFailed>());
    expect((outcome as RevealFailed).code, BiometricError.keyNotFound);
    expect(d.controller.keyState, VaultKeyState.missing);

    // On the next launch the reconciliation finds the same.
    final relaunched = VaultController(d.services);
    await relaunched.start();
    expect(relaunched.phase, VaultPhase.ready);
    expect(relaunched.keyState, VaultKeyState.missing);
    relaunched.dispose();
  });

  test('reconcile on launch detects an invalidated key before any reveal',
      () async {
    final d = await TestDevice.start(DevicePlatform.macos);
    await d.provision(VaultKeyChoice.ec);
    d.fake.simulateBiometricEnrollmentChange();
    final relaunched = VaultController(d.services);
    await relaunched.start();
    expect(relaunched.keyState, VaultKeyState.invalidated);
    expect(relaunched.accessFor(d.services.repository.byId('server-wifi')!),
        ItemAccess.awaitingReseal);
    relaunched.dispose();
  });

  test('a re-provisioning whose registration fails leaves a clear state',
      () async {
    final d = await TestDevice.start(DevicePlatform.android);
    await d.provision(VaultKeyChoice.ec);
    d.fake.simulateBiometricEnrollmentChange();
    await d.controller.refreshKeyHealth();
    d.services.transport.failNext(ProvisioningServer.registerRoute);

    final failed = await d.controller.reprovision();
    expect(failed, isA<RegistrationFailed>());
    // A new key exists, but the server still has the old one.
    expect(d.controller.keyState, VaultKeyState.replaced);
    expect(d.controller.record!.generation, 1);

    final retry = await d.controller.reprovision();
    expect(retry, isA<Provisioned>());
    expect(d.controller.keyState, VaultKeyState.healthy);
    expect(d.controller.record!.generation, 2);
  });

  test('notes cannot be added while the key is unusable', () async {
    final d = await TestDevice.start(DevicePlatform.android);
    await d.provision(VaultKeyChoice.rsa);
    d.fake.invalidate(alias: 'vault');
    await d.controller.refreshKeyHealth();
    expect(() => d.controller.addNote(title: 't', body: 'b'),
        throwsA(isA<StateError>()));
    expect(
        d.controller.accessFor(SealedItem.seal(
          id: 'n',
          title: 'n',
          origin: ItemOrigin.device,
          scheme: d.controller.record!.scheme,
          plaintext: 'x',
          createdAt: DateTime.utc(2026),
        )),
        ItemAccess.lost);
  });
}
