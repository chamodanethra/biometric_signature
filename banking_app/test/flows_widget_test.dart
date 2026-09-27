import 'package:banking_app_example/app.dart';
import 'package:banking_app_example/server/models.dart';
import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/harness.dart';

void main() {
  tearDown(Harness.tearDown);

  Future<void> tapKey(WidgetTester tester, String key) async {
    final finder = find.byKey(ValueKey(key));
    await tester.ensureVisible(finder);
    await tester.pumpAndSettle();
    await tester.tap(finder);
    await tester.pumpAndSettle();
  }

  Future<void> useTallView(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1000, 2600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
  }

  Future<void> bindDevice(WidgetTester tester) async {
    await tapKey(tester, 'send-code');
    await tapKey(tester, 'use-sms-code');
    await tapKey(tester, 'bind-device');
  }

  Future<void> startTransfer(WidgetTester tester, String amount) async {
    await tapKey(tester, 'new-transfer');
    await tester.enterText(find.byKey(const ValueKey('amount-field')), amount);
    await tester.pumpAndSettle();
    await tapKey(tester, 'review-transfer');
  }

  testWidgets(
      'onboarding → tier B transfer → receipt; enrollment change → re-verify',
      (tester) async {
    await useTallView(tester);
    final h = Harness();
    await tester.pumpWidget(BankingApp(services: h.services));
    await tester.pumpAndSettle();

    // Onboarding: preflight passed, bind the device.
    expect(find.text('Bind this device'), findsOneWidget);
    expect(find.text('Screen lock is set'), findsOneWidget);
    await bindDevice(tester);

    // Home.
    expect(find.text('Hi, Alex'), findsOneWidget);
    expect(find.text('Keys registered'), findsOneWidget);
    expect(find.text(r'$5,250.00'), findsOneWidget);

    // Tier B transfer with a live preview.
    await tapKey(tester, 'new-transfer');
    await tester.enterText(find.byKey(const ValueKey('amount-field')), '1250');
    await tester.pumpAndSettle();
    expect(find.text(r'Tier B · ≤ $2,000.00'), findsOneWidget);
    await tapKey(tester, 'review-transfer');

    // Approve: decoded from the issued bytes.
    expect(find.text('What you see is what you sign'), findsOneWidget);
    expect(
        tester.widget<Text>(find.byKey(const ValueKey('approve-amount'))).data,
        r'$1,250.00');
    await tapKey(tester, 'approve');

    // Receipt with the verification trace.
    expect(find.text('Transfer sent'), findsOneWidget);
    expect(find.text('Approval signature'), findsOneWidget);
    expect(find.text('Signed bytes are the bytes the bank issued'),
        findsOneWidget);
    final sign =
        h.fake.calls.lastWhere((c) => c.method == 'createSignatureFromBytes');
    expect(sign.keyAlias, KeyAliases.approval);
    expect((sign.arguments['config'] as CreateSignatureConfig).promptSubtitle,
        r'Pay $1,250.00 to Alice Chen');
    await tapKey(tester, 'receipt-done');
    expect(find.text(r'$4,000.00'), findsOneWidget);

    // A fingerprint is enrolled: the approval key is invalidated.
    h.fake.simulateBiometricEnrollmentChange();
    await startTransfer(tester, '1250');
    await tapKey(tester, 'approve');
    expect(find.text('Approvals locked'), findsOneWidget);
    await tapKey(tester, 'go-reverify');

    // Re-verify: silent device signature + OTP + new attested key.
    expect(find.text('Why re-verify?'), findsOneWidget);
    await tapKey(tester, 'reverify-send-code');
    expect(find.text('Same device'), findsOneWidget);
    await tapKey(tester, 'use-sms-code');
    await tapKey(tester, 'reverify-finish');
    expect(find.byKey(const ValueKey('reverify-success')), findsOneWidget);
    expect(find.text('Old approval key revoked'), findsOneWidget);
    await tapKey(tester, 'reverify-done');

    // Back on the transfer form: approvals are unlocked and the same
    // transfer goes through with the new key.
    expect(h.services.session.approvalsLocked, isFalse);
    expect(find.byKey(const ValueKey('review-transfer')), findsOneWidget);
    await tapKey(tester, 'review-transfer');
    expect(find.text('Approvals locked'), findsNothing);
    await tapKey(tester, 'approve');
    expect(find.text('Transfer sent'), findsOneWidget);
    expect(h.server.devices.single.approvalKeys, hasLength(2));
    await tapKey(tester, 'receipt-done');
    expect(find.byKey(const ValueKey('reverify-banner')), findsNothing);
    expect(find.text(r'$2,750.00'), findsOneWidget);
  });

  testWidgets('iOS: unattested banner and tier C capped in the preview',
      (tester) async {
    await useTallView(tester);
    final h = Harness(platform: DevicePlatform.ios);
    await tester.pumpWidget(BankingApp(services: h.services));
    await tester.pumpAndSettle();
    expect(find.text('Unattested — capped at tier B'), findsOneWidget);
    await bindDevice(tester);
    expect(find.text('Capped at tier B'), findsOneWidget);

    await tapKey(tester, 'new-transfer');
    await tester.enterText(find.byKey(const ValueKey('amount-field')), '2400');
    await tester.pumpAndSettle();
    expect(find.text('Not allowed on this device'), findsOneWidget);
    await tapKey(tester, 'review-transfer');
    expect(find.text('The bank declined this transfer'), findsOneWidget);
  });

  testWidgets('Windows: no background refresh; the banner explains why',
      (tester) async {
    await useTallView(tester);
    final h = Harness(platform: DevicePlatform.windows);
    await tester.pumpWidget(BankingApp(services: h.services));
    await tester.pumpAndSettle();
    await bindDevice(tester);
    expect(
        find.text('Windows Hello prompts for every request'), findsOneWidget);
    // Nothing was fetched automatically after binding.
    expect(h.client.requestLog.entries.map((e) => e.route.path),
        isNot(contains('/accounts')));
    await tapKey(tester, 'load-accounts');
    expect(find.text(r'$5,250.00'), findsOneWidget);
    // Windows keys are RSA; the bank verified them anyway.
    expect(h.server.devices.single.deviceKey.description, 'RSA 2048');
  });
}
