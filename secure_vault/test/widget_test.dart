import 'package:examples_shared/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secure_vault_example/app.dart';

import 'support/test_device.dart';

void main() {
  restorePluginPlatformAfterEachTest();

  void tallView(WidgetTester tester) {
    tester.view.physicalSize = const Size(1000, 2600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
  }

  testWidgets('setup → vault → reveal → auto-hide', (tester) async {
    tallView(tester);
    final device = TestDevice(DevicePlatform.android)..use();
    await tester.pumpWidget(SecureVaultApp(services: device.services));
    await tester.pumpAndSettle();

    expect(find.text('Secrets only your biometrics can open'), findsOneWidget);
    expect(find.text('Screen lock is set'), findsOneWidget);
    expect(find.textContaining('Hybrid mode'), findsOneWidget);

    await tester.tap(find.text('Create vault key'));
    await tester.pumpAndSettle();

    // The vault shows the server's sealed secrets.
    expect(find.text('ECIES (Android hybrid)'), findsOneWidget);
    expect(find.text('Office Wi-Fi password'), findsOneWidget);
    expect(find.text('Account recovery codes'), findsOneWidget);
    expect(find.text('Add note'), findsOneWidget);

    await tester.tap(find.text('Office Wi-Fi password'));
    await tester.pumpAndSettle();
    expect(find.text('Cryptographic gate'), findsOneWidget);
    expect(find.byKey(const ValueKey('plaintext')), findsNothing);

    await tester.tap(find.byKey(const ValueKey('reveal-button')));
    await tester.pump();
    await tester.pump();
    final plaintext = find.byKey(const ValueKey('plaintext'));
    expect(plaintext, findsOneWidget);
    expect(tester.widget<Text>(plaintext).data, 'violet-harbor-42-lantern');
    expect(find.text('Biometric'), findsOneWidget);
    expect(find.text('Hides in 30 s'), findsOneWidget);
    expect(device.callCount('decrypt'), 1);

    await tester.pump(const Duration(seconds: 10));
    expect(find.text('Hides in 20 s'), findsOneWidget);
    await tester.pump(const Duration(seconds: 21));
    expect(plaintext, findsNothing);
    expect(find.byKey(const ValueKey('reveal-button')), findsOneWidget);
  });

  testWidgets('the plaintext hides when the app goes to the background',
      (tester) async {
    tallView(tester);
    final device = TestDevice(DevicePlatform.ios)..use();
    await tester.pumpWidget(SecureVaultApp(services: device.services));
    await tester.pumpAndSettle();
    await tester.tap(find.text('RSA-OAEP'));
    await tester.pumpAndSettle();
    expect(find.textContaining('MGF1-SHA-256'), findsOneWidget);
    await tester.tap(find.text('Create vault key'));
    await tester.pumpAndSettle();
    expect(find.text('RSA-OAEP (Apple)'), findsOneWidget);

    await tester.tap(find.text('Account recovery codes'));
    await tester.pumpAndSettle();
    expect(find.textContaining('wrapped data key'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('reveal-button')));
    await tester.pump();
    await tester.pump();
    expect(find.byKey(const ValueKey('plaintext')), findsOneWidget);

    // resumed → inactive → hidden (backgrounded) → inactive → resumed.
    for (final state in [
      AppLifecycleState.inactive,
      AppLifecycleState.hidden,
      AppLifecycleState.inactive,
      AppLifecycleState.resumed,
    ]) {
      tester.binding.handleAppLifecycleStateChanged(state);
      await tester.pump();
    }
    expect(find.byKey(const ValueKey('plaintext')), findsNothing);
  });

  testWidgets('Windows explains why there is no vault', (tester) async {
    tallView(tester);
    final device = TestDevice(DevicePlatform.windows)..use();
    await tester.pumpWidget(SecureVaultApp(services: device.services));
    await tester.pumpAndSettle();
    expect(find.text('Windows Hello cannot decrypt'), findsOneWidget);
    expect(find.text('Create vault key'), findsNothing);
    expect(find.text('Seal a secret for another vault'), findsOneWidget);
    expect(find.text('Windows Hello is set up'), findsOneWidget);
  });
}
