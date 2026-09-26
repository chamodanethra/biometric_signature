import 'package:biometric_signature/biometric_signature_platform_interface.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/testing.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:passwordless_login_example/app.dart';
import 'package:passwordless_login_example/app_scope.dart';
import 'package:passwordless_login_example/client/accounts.dart';
import 'package:passwordless_login_example/server/models.dart';
import 'package:passwordless_login_example/server/policy.dart';

void main() {
  final original = BiometricSignaturePlatform.instance;
  late SoftwareBiometricPlatform fake;

  tearDown(() {
    BiometricSignaturePlatform.instance = original;
    debugDevicePlatformOverride = null;
  });

  Future<AppServices> pumpApp(
    WidgetTester tester, {
    DevicePlatform platform = DevicePlatform.android,
  }) async {
    tester.view.physicalSize = const Size(1000, 2600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    fake = SoftwareBiometricPlatform(
      simulatedPlatform: platform,
      attestedPackageName: attestedPackageName,
    );
    BiometricSignaturePlatform.instance = fake;
    debugDevicePlatformOverride = platform;
    final services = await AppServices.create(
      platform: platform,
      serverStore: InMemoryKeyValueStore(),
      clientStore: InMemoryKeyValueStore(),
      latency: Duration.zero,
      trustedRootSpkiSha256: {fake.syntheticRootSpkiSha256},
      verifyInIsolate: false,
    );
    await tester.pumpWidget(PasswordlessApp(services: services));
    await tester.pumpAndSettle();
    return services;
  }

  Future<void> tapKey(WidgetTester tester, String key) async {
    final finder = find.byKey(Key(key));
    await tester.ensureVisible(finder);
    await tester.tap(finder);
    await tester.pumpAndSettle();
  }

  Future<void> tapText(WidgetTester tester, String text) async {
    final finder = find.text(text);
    await tester.ensureVisible(finder);
    await tester.tap(finder);
    await tester.pumpAndSettle();
  }

  /// Registers [username] and returns the recovery code shown once.
  Future<String> register(WidgetTester tester, String username) async {
    await tapKey(tester, 'create-account');
    await tester.enterText(find.byKey(const Key('username')), username);
    await tapKey(tester, 'register-submit');
    expect(find.text('Account created'), findsOneWidget);
    final code = tester
        .widget<SelectableText>(find.byKey(const Key('recovery-code')))
        .data!;
    await tapKey(tester, 'report-done');
    return code;
  }

  Future<void> signIn(WidgetTester tester, String username) async {
    await tapKey(tester, 'sign-in-$username');
    await tapKey(tester, 'sign-in');
  }

  testWidgets(
      'register → sign in → key invalidated → re-bind with the recovery code',
      (tester) async {
    final services = await pumpApp(tester);
    final code = await register(tester, 'alice');

    final account = services.accounts.accounts.single;
    expect(account.alias, startsWith('acct_'));
    expect(find.byKey(const ValueKey('account-alice')), findsOneWidget);
    expect(find.text('TEE'), findsWidgets);
    final created = fake.calls.firstWhere((c) => c.method == 'createKeys');
    final config = created.arguments['config']! as CreateKeysConfig;
    expect(config.attestationChallenge, hasLength(32));
    expect(config.failIfExists, isTrue);
    expect(config.enforceBiometric, isTrue);
    expect(config.setInvalidatedByBiometricEnrollment, isTrue);
    expect(config.useDeviceCredentials, isFalse);

    // Sign in: the trace shows the canonical payload and the verdict.
    await signIn(tester, 'alice');
    expect(find.text('ACCEPTED'), findsOneWidget);
    expect(find.textContaining('"purpose":"login"'), findsOneWidget);
    await tapKey(tester, 'continue');
    expect(find.text('Welcome, alice'), findsOneWidget);
    await tapKey(tester, 'sign-out');

    // A new fingerprint is enrolled: the key is permanently invalidated.
    fake.invalidate(alias: account.alias);
    await signIn(tester, 'alice');
    expect(find.text('This device needs a new key'), findsOneWidget);
    expect(services.accounts.statusOf(account.alias).state,
        AccountState.keyInvalidated);

    // Re-bind. The invalidated key still sits under the alias, so
    // failIfExists stops createKeys until the user confirms replacing it.
    await tapKey(tester, 'rebind');
    expect(find.text('Re-bind this device'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('recovery-code-input')), code);
    await tapKey(tester, 'recover-submit');
    expect(find.textContaining('keyAlreadyExists'), findsOneWidget);
    await tapText(tester, 'Delete the old key and continue');
    expect(find.text('Device re-bound'), findsOneWidget);
    final newCode = tester
        .widget<SelectableText>(find.byKey(const Key('recovery-code')))
        .data!;
    expect(newCode, isNot(code));
    await tapKey(tester, 'report-done');

    // Same alias, new key; the server retired the old one.
    final rebound = services.accounts.accounts.single;
    expect(rebound.alias, account.alias);
    expect(rebound.deviceKeyId, isNot(account.deviceKeyId));
    expect(services.server.deviceKey(account.deviceKeyId)!.status,
        DeviceKeyStatus.superseded);
    await signIn(tester, 'alice');
    expect(find.text('ACCEPTED'), findsOneWidget);
  });

  testWidgets('several accounts on one device use separate keys',
      (tester) async {
    final services = await pumpApp(tester);
    await register(tester, 'alice');
    await register(tester, 'bob');

    final accounts = services.accounts.accounts;
    expect(accounts.map((a) => a.username), ['alice', 'bob']);
    expect(accounts[0].alias, isNot(accounts[1].alias));
    expect(accounts[0].publicKeyFingerprint,
        isNot(accounts[1].publicKeyFingerprint));
    expect(find.text('On this device (2)'), findsOneWidget);

    await signIn(tester, 'bob');
    expect(find.text('ACCEPTED'), findsOneWidget);
    final signed =
        fake.calls.lastWhere((c) => c.method == 'createSignatureFromBytes');
    expect(signed.keyAlias, accounts[1].alias);
    expect(signed.arguments['promptMessage'], 'Sign in as bob');
    await tapKey(tester, 'continue');
    expect(find.text('Welcome, bob'), findsOneWidget);
  });

  testWidgets('a key that outlived the app data restores the account',
      (tester) async {
    final services = await pumpApp(tester);
    await register(tester, 'erin');
    final alias = services.accounts.accounts.single.alias;

    // Like an iOS reinstall: preferences are gone, the keychain key is not.
    await services.accounts.clearAll();
    await tester.pumpAndSettle();
    expect(find.text('On this device (0)'), findsOneWidget);

    await tapKey(tester, 'restore-account');
    await tester.enterText(find.byKey(const Key('login-username')), 'erin');
    await tapKey(tester, 'sign-in');
    expect(find.text('Signed in — account restored on this device'),
        findsOneWidget);
    expect(services.accounts.accounts.single.alias, alias);
    expect(
        fake.calls
            .where((c) => c.method == 'getKeyInfo' && c.keyAlias == alias),
        isNotEmpty);
  });

  testWidgets('without the key, restoring points to the recovery code',
      (tester) async {
    final services = await pumpApp(tester);
    await register(tester, 'erin');
    // The server knows the account, but this device has no key for it
    // (e.g. app data restored from a backup onto a new phone).
    await services.client.wipeDevice();
    await tester.pumpAndSettle();

    await tapKey(tester, 'restore-account');
    await tester.enterText(find.byKey(const Key('login-username')), 'erin');
    await tapKey(tester, 'sign-in');
    expect(find.text('This device needs a new key'), findsOneWidget);
    expect(fake.calls.where((c) => c.method == 'createSignatureFromBytes'),
        isEmpty);
  });

  testWidgets('a failed upload is retried with the chain from getKeyInfo',
      (tester) async {
    final services = await pumpApp(tester);
    services.transport.failNext(ApiRoutes.registerFinish);
    await tapKey(tester, 'create-account');
    await tester.enterText(find.byKey(const Key('username')), 'carol');
    await tapKey(tester, 'register-submit');
    expect(find.text('Upload failed — the key is safe'), findsOneWidget);
    expect(services.accounts.pending?.username, 'carol');

    await tapKey(tester, 'retry');
    expect(find.text('Account created'), findsOneWidget);
    expect(fake.calls.where((c) => c.method == 'getKeyInfo'), isNotEmpty);
    expect(services.accounts.pending, isNull);
    expect(services.server.users.single.username, 'carol');
  });

  testWidgets('lockedOutPermanent → unlock with the device credential',
      (tester) async {
    await pumpApp(tester);
    await register(tester, 'alice');
    fake.enqueueResult(FakeOperation.sign, BiometricError.lockedOutPermanent);
    await signIn(tester, 'alice');
    expect(find.text('Biometrics locked (lockedOutPermanent)'), findsOneWidget);

    await tapText(tester, 'Unlock with PIN / passcode');
    final prompt = fake.calls.lastWhere((c) => c.method == 'simplePrompt');
    expect(
        (prompt.arguments['config']! as SimplePromptConfig)
            .allowDeviceCredentials,
        isTrue);
    expect(find.text('ACCEPTED'), findsOneWidget);
  });

  testWidgets(
      'iOS is rejected while attestation is required, then '
      'registers as unattested', (tester) async {
    final services = await pumpApp(tester, platform: DevicePlatform.ios);
    expect(find.text('Attestation is Android-only'), findsOneWidget);

    await tapKey(tester, 'create-account');
    await tester.enterText(find.byKey(const Key('username')), 'dana');
    await tapKey(tester, 'register-submit');
    expect(find.text('Rejected by the server'), findsOneWidget);
    expect(fake.calls.where((c) => c.method == 'createKeys'), isEmpty);

    await services.server.updatePolicy(
        services.server.policy.copyWith(requireAttestation: false));
    await tapKey(tester, 'register-submit');
    expect(find.text('Account created'), findsOneWidget);
    expect(find.text('Trust tier: Not attested'), findsOneWidget);
    final created = fake.calls.firstWhere((c) => c.method == 'createKeys');
    expect(
        (created.arguments['config']! as CreateKeysConfig).attestationChallenge,
        isNull);
  });
}
