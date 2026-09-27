import 'package:examples_shared/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secure_vault_example/app.dart';
import 'package:secure_vault_example/client/sharing.dart';
import 'package:secure_vault_example/client/vault_controller.dart';

import 'support/test_device.dart';

void main() {
  restorePluginPlatformAfterEachTest();

  for (final (width, brightness) in [
    (360.0, Brightness.light),
    (1024.0, Brightness.dark),
  ]) {
    testWidgets('every screen renders at ${width.toInt()} px, $brightness',
        (tester) async {
      tester.view.physicalSize = Size(width, 1400);
      tester.view.devicePixelRatio = 1;
      tester.platformDispatcher.platformBrightnessTestValue = brightness;
      addTearDown(tester.view.reset);
      addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);

      final device = TestDevice(DevicePlatform.android)..use();
      await tester.pumpWidget(SecureVaultApp(services: device.services));
      await tester.pumpAndSettle();
      // The app's own controller (SecureVaultApp creates it).
      final controller =
          AppScope.read(tester.element(find.byType(MaterialApp)));

      // Setup, with the server console open before provisioning.
      await _openConsole(tester);

      await tester.scrollUntilVisible(find.text('Create vault key'), 200,
          scrollable: find.byType(Scrollable).first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Create vault key'));
      await tester.pumpAndSettle();
      expect(find.text('Two kinds of gate'), findsOneWidget);

      // UI gate: hide titles, unlock them with simplePrompt.
      await tester.tap(find.text('Hide titles until unlocked'));
      await tester.pumpAndSettle();
      expect(find.text('Office Wi-Fi password'), findsNothing);
      await tester.tap(find.text('Show titles (simplePrompt)'));
      await tester.pumpAndSettle();
      expect(device.callCount('simplePrompt'), 1);
      expect(device.callCount('decrypt'), 0);
      await tester.scrollUntilVisible(find.text('Office Wi-Fi password'), 200,
          scrollable: find.byType(Scrollable).first);
      await tester.pumpAndSettle();
      expect(find.text('Office Wi-Fi password'), findsOneWidget);
      await tester.scrollUntilVisible(
          find.text('Hide titles until unlocked'), -200,
          scrollable: find.byType(Scrollable).first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Hide titles until unlocked'));
      await tester.pumpAndSettle();

      // Add a note (no prompt).
      await tester.tap(find.text('Add note'));
      await tester.pumpAndSettle();
      await tester.enterText(find.widgetWithText(TextField, 'Title'), 'Safe');
      await tester.enterText(find.widgetWithText(TextField, 'Secret'), '1-2-3');
      await tester.pump();
      expect(find.text('5 bytes → sealed directly'), findsOneWidget);
      await tester.tap(find.text('Seal note'));
      await tester.pumpAndSettle();
      expect(device.callCount('decrypt'), 0);
      expect(device.services.repository.items.where((i) => i.title == 'Safe'),
          hasLength(1));

      // Key status.
      await tester.tap(find.byTooltip('Key status'));
      await tester.pumpAndSettle();
      expect(find.text('Key present and valid'), findsOneWidget);
      expect(find.text('decryptingPublicKey fingerprint'), findsOneWidget);
      await tester.pageBack();
      await tester.pumpAndSettle();

      // Share: address, seal (to ourselves), import.
      await tester.tap(find.byTooltip('Share'));
      await tester.pumpAndSettle();
      expect(find.text('Vault address (JSON)'), findsOneWidget);
      final address = (await controller.myAddress()).encode();
      await tester.tap(find.text('Seal for someone'));
      await tester.pumpAndSettle();
      await tester.enterText(
          find.widgetWithText(TextField, "Recipient's vault address (JSON)"),
          address);
      await tester.tap(find.text('Check address'));
      await tester.pumpAndSettle();
      expect(find.text('Consistent'), findsOneWidget);
      final sealed = sealForRecipient(VaultAddress.parse(address),
          title: 'Gift', secret: 'for me', from: 'me');
      await tester.tap(find.text('Import'));
      await tester.pumpAndSettle();
      await tester.enterText(
          find.widgetWithText(TextField, 'Sealed item (JSON)'), sealed);
      await tester.tap(find.byIcon(Icons.move_to_inbox_outlined));
      await tester.pumpAndSettle();
      expect(device.services.repository.items.where((i) => i.title == 'Gift'),
          hasLength(1));
      await tester.pageBack();
      await tester.pumpAndSettle();

      // Crypto-shredding: invalidate, reveal fails, re-provision.
      device.fake.simulateBiometricEnrollmentChange();
      await controller.refreshKeyHealth();
      await tester.pumpAndSettle();
      expect(find.textContaining('Vault key invalidated'), findsOneWidget);
      expect(find.text('Add note'), findsNothing);
      await tester.tap(find.widgetWithText(FilledButton, 'Re-provision'));
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(FilledButton, 'Re-provision').last);
      await tester.pumpAndSettle();
      expect(controller.record!.generation, 2);
      expect(find.text('2 items can never be opened'), findsOneWidget);

      // An unrecoverable item's screen.
      await tester.scrollUntilVisible(find.text('Safe'), 200,
          scrollable: find.byType(Scrollable).first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Safe'));
      await tester.pumpAndSettle();
      expect(find.text('Unrecoverable'), findsWidgets);
      await tester.pageBack();
      await tester.pumpAndSettle();

      // Console tabs after provisioning, then reset.
      await _openConsole(tester, close: false);
      await tester.ensureVisible(find.text('Faults'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Faults'));
      await tester.pumpAndSettle();
      await tester
          .tap(find.textContaining('the AES-GCM content of an envelope'));
      await tester.pumpAndSettle();
      expect(find.text('Armed'), findsOneWidget);
      await tester.scrollUntilVisible(find.text('Reset demo'), 200,
          scrollable: find
              .ancestor(
                  of: find.text('Network faults'),
                  matching: find.byType(Scrollable))
              .first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Reset demo'));
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(FilledButton, 'Reset'));
      await tester.pumpAndSettle();
      expect(
          find.text('Secrets only your biometrics can open'), findsOneWidget);
      expect(controller.phase, VaultPhase.setup);
      expect(device.callCount('deleteAllKeys'), 1);
    });
  }
}

Future<void> _openConsole(WidgetTester tester, {bool close = true}) async {
  await tester.tap(find.byTooltip('Server console'));
  await tester.pumpAndSettle();
  for (final tab in ['Audit', 'Wire', 'Faults', 'Records']) {
    await tester.ensureVisible(find.text(tab));
    await tester.pumpAndSettle();
    await tester.tap(find.text(tab));
    await tester.pumpAndSettle();
  }
  expect(find.text('Server secrets'), findsOneWidget);
  if (!close) return;
  await tester.tapAt(const Offset(10, 10));
  await tester.pumpAndSettle();
}
