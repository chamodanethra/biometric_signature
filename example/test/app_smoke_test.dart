import 'package:biometric_signature/biometric_signature_platform_interface.dart';
import 'package:biometric_signature_example/app.dart';
import 'package:biometric_signature_example/state/explorer_state.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/testing.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// Verifies synchronously (no isolate, which widget tests cannot await)
/// and trusts the fake platform's synthetic attestation root.
AttestationInspector _trustingSynthetic(String rootSpkiSha256) => ({
      required chain,
      required expectedChallenge,
      required expectedPublicKey,
    }) async =>
        AttestationVerifier(trustedRootSpkiSha256: {rootSpkiSha256}).verify(
          chain: chain,
          expectedChallenge: expectedChallenge,
          expectedPublicKey: expectedPublicKey,
        );

Future<SoftwareBiometricPlatform> _pumpExplorer(
  WidgetTester tester,
  DevicePlatform platform, {
  Size size = const Size(480, 1000),
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  debugDevicePlatformOverride = platform;
  final fake = SoftwareBiometricPlatform(simulatedPlatform: platform);
  BiometricSignaturePlatform.instance = fake;
  await tester.pumpWidget(ExplorerApp(
    attestationInspector: _trustingSynthetic(fake.syntheticRootSpkiSha256),
  ));
  await tester.pumpAndSettle();
  return fake;
}

Future<void> _go(WidgetTester tester, ExplorerDestination d) async {
  final bar = find.byType(NavigationBar).evaluate().isNotEmpty
      ? find.byType(NavigationBar)
      : find.byType(NavigationRail);
  final icon = find.descendant(of: bar, matching: find.byIcon(d.icon));
  final target = icon.evaluate().isNotEmpty
      ? icon.first
      : find.descendant(of: bar, matching: find.byIcon(d.selectedIcon)).first;
  // The rail scrolls on short, wide screens.
  await tester.ensureVisible(target);
  await tester.pumpAndSettle();
  await tester.tap(target);
  await tester.pumpAndSettle();
  expect(find.byKey(ValueKey('screen.${d.name}')), findsOneWidget);
}

Future<void> _tap(WidgetTester tester, Finder finder) async {
  await tester.ensureVisible(finder);
  await tester.pumpAndSettle();
  await tester.tap(finder);
  await tester.pumpAndSettle();
}

Future<void> _tapKey(WidgetTester tester, String key) =>
    _tap(tester, find.byKey(ValueKey(key)));

Future<void> _choose(WidgetTester tester, String controlKey, String label) =>
    _tap(
      tester,
      find.descendant(
        of: find.byKey(ValueKey(controlKey)),
        matching: find.text(label),
      ),
    );

void main() {
  late BiometricSignaturePlatform original;

  setUpAll(() => original = BiometricSignaturePlatform.instance);
  tearDownAll(() => BiometricSignaturePlatform.instance = original);
  tearDown(() => debugDevicePlatformOverride = null);

  testWidgets('narrow Android layout: every destination renders',
      (tester) async {
    final fake = await _pumpExplorer(tester, DevicePlatform.android,
        size: const Size(360, 740));
    expect(find.byType(NavigationBar), findsOneWidget);
    // Availability and device lock are read on launch.
    expect(fake.calls.map((c) => c.method),
        containsAll(['biometricAuthAvailable', 'isDeviceLockSet']));
    expect(find.text('canAuthenticate'), findsOneWidget);
    for (final d in ExplorerDestination.values.reversed) {
      await _go(tester, d);
      expect(tester.takeException(), isNull);
    }
  });

  testWidgets('wide iOS layout uses a navigation rail', (tester) async {
    await _pumpExplorer(tester, DevicePlatform.ios,
        size: const Size(1200, 900));
    expect(find.byType(NavigationRail), findsOneWidget);
    expect(find.byType(NavigationBar), findsNothing);
    for (final d in ExplorerDestination.values) {
      await _go(tester, d);
      expect(tester.takeException(), isNull);
    }
  });

  testWidgets('landscape phone: the rail scrolls instead of overflowing',
      (tester) async {
    await _pumpExplorer(tester, DevicePlatform.android,
        size: const Size(900, 400));
    expect(find.byType(NavigationRail), findsOneWidget);
    await _go(tester, ExplorerDestination.errors);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
      'Android hybrid EC: createKeys → sign → verify → decrypt round trip',
      (tester) async {
    final fake = await _pumpExplorer(tester, DevicePlatform.android,
        size: const Size(360, 740));

    await _go(tester, ExplorerDestination.keys);
    await _tapKey(tester, 'keys.preset.ecWithDecryption');
    await _tapKey(tester, 'keys.create');
    expect(find.byKey(const ValueKey('keys.result')), findsOneWidget);
    final key = fake.keyFor('explorer_a')!;
    expect(key.isRsa, isFalse);
    expect(key.decryptingKey, isNotNull);
    expect(find.text('isHybridMode: true'), findsOneWidget);

    await _go(tester, ExplorerDestination.sign);
    await _tapKey(tester, 'sign.run');
    expect(find.byKey(const ValueKey('sign.result')), findsOneWidget);
    await _tapKey(tester, 'sign.verify');
    // Against the returned key and against the createKeys key.
    expect(find.text('Signature is valid'), findsNWidgets(2));
    expect(find.text('Tampered message (one bit flipped) is rejected'),
        findsOneWidget);

    // Text mode with the hex signature format verifies too.
    await _choose(tester, 'sign.mode', 'createSignature (text)');
    await _choose(tester, 'sign.signatureFormat', 'hex');
    await _tapKey(tester, 'sign.run');
    await _tapKey(tester, 'sign.verify');
    expect(find.text('Signature is valid'), findsNWidgets(2));
    expect(fake.calls.map((c) => c.method),
        containsAll(['createSignature', 'createSignatureFromBytes']));

    await _go(tester, ExplorerDestination.decrypt);
    await _tapKey(tester, 'decrypt.encrypt');
    expect(find.text('ECIES (Android hybrid)'), findsOneWidget);
    await _tapKey(tester, 'decrypt.run');
    expect(find.text('Round trip OK: decryptedData equals the plaintext'),
        findsOneWidget);

    // The same ciphertext as hex, and as "raw" (base64 text).
    for (final format in ['hex', 'raw']) {
      await _choose(tester, 'decrypt.payloadFormat', format);
      await _tapKey(tester, 'decrypt.run');
      expect(find.text('Round trip OK: decryptedData equals the plaintext'),
          findsOneWidget,
          reason: format);
    }
  });

  testWidgets('Apple EC: Secure Enclave key signs and decrypts (Apple ECIES)',
      (tester) async {
    final fake = await _pumpExplorer(tester, DevicePlatform.ios,
        size: const Size(360, 740));

    await _go(tester, ExplorerDestination.keys);
    await _tapKey(tester, 'keys.create');
    expect(fake.keyFor('explorer_a')?.isRsa, isFalse);
    expect(find.text('isHybridMode: false'), findsOneWidget);

    await _go(tester, ExplorerDestination.sign);
    await _tapKey(tester, 'sign.run');
    await _tapKey(tester, 'sign.verify');
    expect(find.text('Signature is valid'), findsNWidgets(2));

    await _go(tester, ExplorerDestination.decrypt);
    await _tapKey(tester, 'decrypt.encrypt');
    expect(find.text('ECIES (Apple Secure Enclave)'), findsOneWidget);
    await _tapKey(tester, 'decrypt.run');
    expect(find.text('Round trip OK: decryptedData equals the plaintext'),
        findsOneWidget);
  });

  testWidgets('Apple RSA: OAEP with MGF1-SHA-256 decrypts', (tester) async {
    await _pumpExplorer(tester, DevicePlatform.macos);
    await _go(tester, ExplorerDestination.keys);
    await _tapKey(tester, 'keys.preset.rsaWithDecryption');
    await _tapKey(tester, 'keys.create');
    await _go(tester, ExplorerDestination.decrypt);
    await _tapKey(tester, 'decrypt.encrypt');
    expect(find.text('RSA-OAEP (Apple)'), findsOneWidget);
    await _tapKey(tester, 'decrypt.run');
    expect(find.text('Round trip OK: decryptedData equals the plaintext'),
        findsOneWidget);
  });

  testWidgets('Android attestation: report, and 129 bytes is invalidInput',
      (tester) async {
    await _pumpExplorer(tester, DevicePlatform.android);
    await _go(tester, ExplorerDestination.keys);
    await _tapKey(tester, 'keys.attestation.32');
    await _tapKey(tester, 'keys.create');
    expect(
      find.text('Local inspection (demo) — a real server issues the '
          'challenge and verifies'),
      findsOneWidget,
    );
    expect(find.text('Challenge matches'), findsOneWidget);
    expect(find.text('Attested key is the registered key'), findsOneWidget);
    expect(find.text('Copy chain as PEM'), findsOneWidget);

    await _tapKey(tester, 'keys.attestation.129');
    await _tapKey(tester, 'keys.create');
    expect(find.textContaining('(invalidInput)'), findsOneWidget);
    expect(find.byKey(const ValueKey('attestation.section')), findsNothing);
  });

  testWidgets('Errors: keyAlreadyExists and keyNotFound triggers',
      (tester) async {
    final fake = await _pumpExplorer(tester, DevicePlatform.android);
    await _go(tester, ExplorerDestination.errors);

    await _tapKey(tester, 'errors.keyAlreadyExists.run');
    expect(find.text('Got keyAlreadyExists, as expected.'), findsOneWidget);
    expect(fake.keyFor('explorer_errors'), isNull,
        reason: 'the scratch key is deleted again');

    await _tapKey(tester, 'errors.keyNotFound.run');
    expect(find.text('Got keyNotFound, as expected.'), findsOneWidget);

    await _tapKey(tester, 'errors.invalidInputEmptyPayload.run');
    expect(find.text('Got invalidInput, as expected.'), findsOneWidget);

    // Every code is listed.
    for (final code in BiometricError.values) {
      expect(find.byKey(ValueKey('errors.code.${code.name}')), findsOneWidget);
    }
  });

  testWidgets('Windows: EC and decrypt are disabled with explanations',
      (tester) async {
    await _pumpExplorer(tester, DevicePlatform.windows);
    await _go(tester, ExplorerDestination.keys);
    expect(find.text('RSA only on Windows'), findsOneWidget);
    expect(find.text('Not available on Windows'), findsOneWidget);

    await _go(tester, ExplorerDestination.decrypt);
    expect(find.byKey(const ValueKey('decrypt.unsupported')), findsOneWidget);
    expect(find.byKey(const ValueKey('decrypt.encrypt')), findsNothing);
    await _tapKey(tester, 'decrypt.anyway');
    expect(find.textContaining('(notAvailable)'), findsOneWidget);
  });

  testWidgets('Inventory: getKeyInfo, deleteKeys and confirmed deleteAllKeys',
      (tester) async {
    final fake = await _pumpExplorer(tester, DevicePlatform.android);
    await _go(tester, ExplorerDestination.keys);
    await _tapKey(tester, 'keys.create');

    await _go(tester, ExplorerDestination.inventory);
    await _tapKey(tester, 'inventory.refreshAll');
    expect(find.text('key present'), findsOneWidget);
    expect(find.text('no key'), findsNWidgets(3));

    await _tapKey(tester, 'inventory.exists.explorer_a');
    expect(find.text('true (checkValidity: true)'), findsOneWidget);

    await _tapKey(tester, 'inventory.delete.explorer_a');
    expect(fake.keyFor('explorer_a'), isNull);
    expect(fake.calls.last.method, 'deleteKeys');

    await _go(tester, ExplorerDestination.keys);
    await _tapKey(tester, 'keys.create');
    await _go(tester, ExplorerDestination.inventory);

    await _tapKey(tester, 'inventory.deleteAll');
    expect(find.text('Delete every key?'), findsOneWidget);
    await _tapKey(tester, 'inventory.deleteAll.confirm');
    expect(fake.aliases, isEmpty);
    expect(fake.calls.last.method, 'deleteAllKeys');
  });

  testWidgets('Call log copies a call as Dart', (tester) async {
    String? copied;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = (call.arguments as Map)['text'] as String?;
        }
        return null;
      },
    );
    addTearDown(() => tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null));

    await _pumpExplorer(tester, DevicePlatform.android);
    await tester.tap(find.byTooltip('Call log'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('isDeviceLockSet'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Copy as Dart'));
    await tester.pump();
    expect(copied, contains('return BiometricSignature().isDeviceLockSet();'));
    // Let the confirmation snack bar time out.
    await tester.pump(const Duration(seconds: 3));
    await tester.pumpAndSettle();
  });
}
