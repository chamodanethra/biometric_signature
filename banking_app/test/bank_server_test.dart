import 'dart:convert';

import 'package:banking_app_example/client/approval_service.dart';
import 'package:banking_app_example/client/bank_client.dart';
import 'package:banking_app_example/client/key_setup.dart';
import 'package:banking_app_example/client/transaction_payload.dart';
import 'package:banking_app_example/server/models.dart';
import 'package:banking_app_example/server/request_signing.dart';
import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/testing.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/harness.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  tearDown(Harness.tearDown);

  ServerCheck check(List<ServerCheck> checks, String id) =>
      checks.singleWhere((c) => c.id == id);

  group('enrollment', () {
    test('Android: both keys attested; approval key biometric-only', () async {
      final h = Harness();
      final result = await h.enroll();
      expect(result.checks.every((c) => !c.failed), isTrue,
          reason: '${result.checks}');
      expect(result.requestChecks.every((c) => !c.failed), isTrue);
      final device = result.device;
      expect(device.deviceKey.trustTier, TrustTier.tee);
      expect(device.deviceKey.attestedNoAuthRequired, isTrue);
      expect(device.activeApprovalKey!.attestedBiometricOnly, isTrue);
      expect(check(result.checks, 'policy.tierC').status, CheckStatus.pass);

      // The plugin was asked for exactly what the story needs.
      final creates =
          h.fake.calls.where((c) => c.method == 'createKeys').toList();
      final deviceConfig = creates
          .singleWhere((c) => c.keyAlias == KeyAliases.deviceBinding)
          .arguments['config'] as CreateKeysConfig;
      expect(deviceConfig.requireAuthentication, isFalse);
      expect(deviceConfig.failIfExists, isTrue);
      expect(deviceConfig.attestationChallenge, isNotNull);
      final approvalConfig = creates
          .singleWhere((c) => c.keyAlias == KeyAliases.approval)
          .arguments['config'] as CreateKeysConfig;
      expect(approvalConfig.enforceBiometric, isTrue);
      expect(approvalConfig.setInvalidatedByBiometricEnrollment, isTrue);
      expect(approvalConfig.useDeviceCredentials, isFalse);
      expect(approvalConfig.failIfExists, isTrue);
    });

    test('a wrong one-time code is rejected; the retry reuses the keys',
        () async {
      final h = Harness();
      await h.services.start();
      final attempt = DeviceEnrollment(keys: h.services.keys, client: h.client);
      final start = await attempt.begin();
      await expectLater(
        attempt.complete(otp: '000000', allowDeviceCredential: false),
        throwsA(
            isA<BankError>().having((e) => e.reasonCode, 'reasonCode', 'otp')),
      );
      final keysCreated =
          h.fake.calls.where((c) => c.method == 'createKeys').length;
      final code = h.server.outbox.latestFor(start.enrollmentId)!.code;
      final result =
          await attempt.complete(otp: code, allowDeviceCredential: false);
      expect(result.device.isActive, isTrue);
      expect(h.fake.calls.where((c) => c.method == 'createKeys').length,
          keysCreated);
    });

    test('keyAlreadyExists from an earlier install is surfaced', () async {
      final h = Harness();
      await h.services.api.createKeys(
        keyAlias: KeyAliases.deviceBinding,
        config: CreateKeysConfig(requireAuthentication: false),
      );
      await h.services.start();
      final attempt = DeviceEnrollment(keys: h.services.keys, client: h.client);
      final start = await attempt.begin();
      final code = h.server.outbox.latestFor(start.enrollmentId)!.code;
      await expectLater(
        attempt.complete(otp: code, allowDeviceCredential: false),
        throwsA(isA<KeySetupException>()
            .having((e) => e.code, 'code', BiometricError.keyAlreadyExists)),
      );
      await attempt.replaceExisting(KeyAliases.deviceBinding);
      final result =
          await attempt.complete(otp: code, allowDeviceCredential: false);
      expect(result.device.deviceKey.trustTier, TrustTier.tee);
    });

    test('an Android keystore that cannot attest: unattested, capped at B',
        () async {
      final h = Harness();
      h.fake.attestationMode = FakeAttestationMode.notSupported;
      final result = await h.enroll();
      expect(result.device.activeApprovalKey!.trustTier, TrustTier.none);
      expect(check(result.checks, 'policy.tierC').status, CheckStatus.warn);
      await expectLater(
          h.prepare(240000),
          throwsA(isA<BankError>().having(
              (e) => e.message, 'message', contains('could not attest'))));
    });
  });

  group('tiers', () {
    test('tier A: signed silently by device_binding', () async {
      final h = Harness();
      await h.enroll();
      final before = h.checkingBalance;
      final result = await h.transfer(4500);
      expect(result.accepted, isTrue, reason: result.reason);
      expect(h.checkingBalance, before - 4500);
      final sign =
          h.fake.calls.lastWhere((c) => c.method == 'createSignatureFromBytes');
      expect(sign.keyAlias, KeyAliases.deviceBinding);
      expect(sign.arguments['config'], isNull);
      expect(result.transfer!.signer, KeyAliases.deviceBinding);
      expect(check(result.checks, 'auth.type').detail, contains('Silent'));
    });

    test('tier B: txn_approval with the amount in the prompt', () async {
      final h = Harness();
      await h.enroll();
      final result = await h.transfer(125000);
      expect(result.accepted, isTrue, reason: result.reason);
      expect(result.transfer!.tier, RiskTier.b);
      expect(result.transfer!.authenticationType, 'biometric');
      final sign =
          h.fake.calls.lastWhere((c) => c.method == 'createSignatureFromBytes');
      expect(sign.keyAlias, KeyAliases.approval);
      expect(
          sign.arguments['promptMessage'], r'Approve $1,250.00 to Alice Chen');
      final config = sign.arguments['config'] as CreateSignatureConfig;
      expect(config.promptSubtitle, r'Pay $1,250.00 to Alice Chen');
      expect(config.promptDescription, startsWith('Ref TX-'));
      expect(config.promptDescription, endsWith('from ••4821'));
      expect(config.cancelButtonText, "Don't approve");
      expect(config.allowDeviceCredentials, isFalse);
    });

    test('tier C: accepted with an attested biometric-only key', () async {
      final h = Harness();
      await h.enroll();
      final result = await h.transfer(240000);
      expect(result.accepted, isTrue, reason: result.reason);
      expect(check(result.checks, 'tier.policy').detail,
          contains('hardware key attestation'));
    });

    test('tier C: declined for a key attested biometric-or-PIN', () async {
      final h = Harness();
      await h.enroll(allowPin: true);
      await expectLater(
        h.prepare(240000),
        throwsA(isA<BankError>()
            .having((e) => e.reasonCode, 'reasonCode', 'tier')
            .having((e) => e.message, 'message',
                contains('biometric OR device PIN'))),
      );
      expect((await h.transfer(125000)).accepted, isTrue);
    });

    test('simulated iOS: capped at tier B; toggle off accepts declared keys',
        () async {
      final h = Harness(platform: DevicePlatform.ios);
      final result = await h.enroll();
      expect(result.device.activeApprovalKey!.trustTier, TrustTier.none);
      expect(
          h.fake.calls.where((c) => c.method == 'createKeys').every((c) =>
              (c.arguments['config'] as CreateKeysConfig)
                  .attestationChallenge ==
              null),
          isTrue,
          reason: 'no attestation challenge off Android');
      await expectLater(
        h.prepare(240000),
        throwsA(isA<BankError>().having(
            (e) => e.message, 'message', contains('iOS has no per-key'))),
      );
      expect((await h.transfer(125000)).accepted, isTrue);

      await h.server.updatePolicy(h.server.policy
          .copyWith(requireAttestedBiometricOnlyForTierC: false));
      final c = await h.transfer(240000);
      expect(c.accepted, isTrue, reason: c.reason);
      expect(check(c.checks, 'tier.policy').detail, contains('not verified'));
    });

    test('a tier B payload signed with device_binding is rejected', () async {
      final h = Harness();
      await h.enroll();
      final prepared = await h.prepare(125000);
      final sig = await h.services.api.createSignatureFromBytes(
          payload: prepared.payload.bytes, keyAlias: KeyAliases.deviceBinding);
      final result = await h.client.confirmTransfer(
        txnId: prepared.payload.txnId,
        payload: prepared.payload.bytes,
        signature: sig.signature!,
        signer: KeyAliases.deviceBinding,
        authenticationType: sig.authenticationType,
      );
      expect(result.accepted, isFalse);
      expect(check(result.checks, 'tier.signer').failed, isTrue);
      expect(check(result.checks, 'signature').failed, isFalse);
    });
  });

  group('attacks', () {
    test('network tamper after signing: request signature mismatch', () async {
      final h = Harness();
      await h.enroll();
      final before = h.checkingBalance;
      h.services.transport.tamper(BankRoutes.confirm.path, 'body.payload',
          TransactionPayload.tamperAmount(900000));
      final result = await h.transfer(125000);
      expect(result.accepted, isFalse);
      expect(result.requestOk, isFalse);
      expect(check(result.requestChecks, 'request.signature').detail,
          contains('Signature mismatch'));
      expect(result.checks, isEmpty);
      expect(h.checkingBalance, before);
      expect(h.client.requestLog.entries.last.status, RequestStatus.rejected);
    });

    test('compromised app changes the amount after a biometric approval',
        () async {
      final h = Harness();
      await h.enroll();
      final before = h.checkingBalance;
      h.client.faults.alterAmountAfterApproval = true;
      final outcome = await h.approve(await h.prepare(125000));
      final result = (outcome as ApprovalSubmitted).result;
      expect(outcome.fault, isNotNull);
      expect(result.requestOk, isTrue);
      expect(result.accepted, isFalse);
      expect(check(result.checks, 'signature').detail,
          contains('Signature mismatch'));
      expect(check(result.checks, 'payload.issued').detail,
          contains('amountCents: 125000 → 1025000'));
      expect(h.checkingBalance, before);
    });

    test('tier A: re-signing with the silent key still fails (not issued)',
        () async {
      final h = Harness();
      await h.enroll();
      h.client.faults.alterAmountAfterApproval = true;
      final outcome = await h.approve(await h.prepare(4500));
      final result = (outcome as ApprovalSubmitted).result;
      expect(result.accepted, isFalse);
      expect(check(result.checks, 'signature').failed, isFalse,
          reason: 'malware can sign anything with the silent key');
      expect(check(result.checks, 'payload.issued').failed, isTrue);
    });

    test('replays: captured request (request id) and fresh request (nonce)',
        () async {
      final h = Harness();
      await h.enroll();
      expect((await h.transfer(125000)).accepted, isTrue);
      final afterFirst = h.checkingBalance;

      final replayed = BankClient.parseConfirmResponse(
          await h.services.transport.replayLast(BankRoutes.confirm.path));
      expect(replayed.requestOk, isFalse);
      expect(check(replayed.requestChecks, 'request.replay').failed, isTrue);

      final resubmitted = await h.client.resubmitLastConfirm();
      expect(resubmitted.requestOk, isTrue);
      expect(resubmitted.accepted, isFalse);
      expect(check(resubmitted.checks, 'txn.nonce').detail,
          contains('already submitted'));
      expect(h.checkingBalance, afterFirst);
    });

    test('the payload expires after the approval window', () async {
      final h = Harness();
      await h.enroll();
      final prepared = await h.prepare(125000);
      h.clock.advance(const Duration(seconds: 121));
      final outcome = await h.approve(prepared);
      final result = (outcome as ApprovalSubmitted).result;
      expect(result.requestOk, isTrue);
      expect(result.accepted, isFalse);
      expect(check(result.checks, 'txn.expiry').failed, isTrue);
    });

    test('device clock skew beyond ±60 s: rejected before any handler',
        () async {
      final h = Harness();
      await h.enroll();
      h.deviceClock.skew = const Duration(seconds: 90);
      await expectLater(
        h.client.fetchAccounts(),
        throwsA(isA<BankError>()
            .having((e) => e.reasonCode, 'reasonCode', 'timestamp')),
      );
      h.deviceClock.skew = const Duration(seconds: 30);
      await h.client.fetchAccounts();
    });

    test('an injected network failure surfaces as a network error', () async {
      final h = Harness();
      await h.enroll();
      h.services.transport.failNext('*');
      await expectLater(
          h.client.fetchAccounts(),
          throwsA(isA<BankError>()
              .having((e) => e.kind, 'kind', BankErrorKind.network)));
      await h.client.fetchAccounts();
    });
  });

  test('anomaly: a credential reported for a biometric-only key is flagged',
      () async {
    final h = Harness(authenticationType: AuthenticationType.credential);
    await h.enroll();
    final result = await h.transfer(125000);
    expect(result.accepted, isTrue, reason: 'flagged, not blocked');
    expect(result.transfer!.anomaly, isTrue);
    final auth = check(result.checks, 'auth.type');
    expect(auth.status, CheckStatus.warn);
    expect(auth.detail, contains('attested biometric-only'));
    expect(h.server.audit.entries.map((e) => e.event),
        contains('transfer.anomaly'));
  });

  group('recovery', () {
    test('invalidated approval key → re-verify with the silent key + OTP',
        () async {
      final h = Harness();
      await h.enroll();
      final oldKey = h.server.devices.single.activeApprovalKey!;
      h.fake.simulateBiometricEnrollmentChange();

      final outcome = await h.approve(await h.prepare(125000));
      expect(outcome, isA<ApprovalNeedsReverification>());
      expect((outcome as ApprovalNeedsReverification).code,
          BiometricError.keyInvalidated);
      // The silent device key is not invalidated: requests still work.
      await h.client.fetchAccounts();
      expect((await h.transfer(4500)).accepted, isTrue);

      await h.services.session.recheckKeys();
      expect(h.services.session.approvalsLocked, isTrue);

      final reverify = ApprovalKeyReverification(
          keys: h.services.keys, client: h.client, reason: 'keyInvalidated');
      final start = await reverify.begin();
      expect(check(start.checks, 'reverify.device').status, CheckStatus.pass);
      final code = h.server.outbox.latestFor(start.reverifyId)!.code;
      final result =
          await reverify.complete(otp: code, allowDeviceCredential: false);
      await h.services.session.completeReverification(result,
          key: reverify.newKey!, allowDeviceCredential: false);

      final device = h.server.devices.single;
      expect(device.approvalKeys, hasLength(2));
      expect(device.approvalKeys.first.status, KeyStatus.revoked);
      expect(
          device.approvalKeys.first.revokeReason, contains('keyInvalidated'));
      expect(device.activeApprovalKey!.fingerprint, isNot(oldKey.fingerprint));
      expect(device.activeApprovalKey!.attestedBiometricOnly, isTrue);
      expect(h.services.session.approvalsLocked, isFalse);
      expect((await h.transfer(125000)).accepted, isTrue);
    });

    test('device_binding keyNotFound → back to onboarding', () async {
      final h = Harness();
      await h.enroll();
      final oldDevice = h.services.session.enrollment!.deviceId;
      await h.services.api.deleteKeys(keyAlias: KeyAliases.deviceBinding);
      await h.services.session.refresh();
      expect(h.services.session.isEnrolled, isFalse);
      expect(h.services.session.bindingLostReason, contains('missing'));
      expect(h.services.session.previousDeviceId, oldDevice);

      // Re-binding retires the old record at the bank.
      await h.services.api.deleteAllKeys();
      final attempt = DeviceEnrollment(
          keys: h.services.keys,
          client: h.client,
          previousDeviceId: h.services.session.previousDeviceId);
      final start = await attempt.begin();
      final result = await attempt.complete(
          otp: h.server.outbox.latestFor(start.enrollmentId)!.code,
          allowDeviceCredential: false);
      expect(check(result.checks, 'enroll.previous').status, CheckStatus.info);
      expect(h.server.device(oldDevice)!.status, DeviceStatus.replaced);
    });

    test('bootstrap reconciles a restored binding without keys', () async {
      final h = Harness();
      await h.enroll();
      await h.services.api.deleteAllKeys();
      await h.services.session.bootstrap();
      expect(h.services.session.isEnrolled, isFalse);
      expect(h.services.session.bindingLostReason, isNotNull);
    });

    test('unbind revokes the device and deletes both keys', () async {
      final h = Harness();
      await h.enroll();
      final id = h.services.session.enrollment!.deviceId;
      await h.services.unbindDevice();
      expect(h.server.device(id)!.status, DeviceStatus.unbound);
      expect(h.fake.aliases, isEmpty);
      expect(h.services.session.isEnrolled, isFalse);
    });

    test('reset demo deletes all keys and forgets everything', () async {
      final h = Harness();
      await h.enroll();
      await h.transfer(4500);
      await h.services.resetDemo();
      expect(h.fake.calls.map((c) => c.method), contains('deleteAllKeys'));
      expect(h.fake.aliases, isEmpty);
      expect(h.server.devices, isEmpty);
      expect(h.server.transfers, isEmpty);
      expect(h.checkingBalance, 525000);
      expect(h.services.session.isEnrolled, isFalse);
    });
  });

  test('the issued payload is canonical and decodes strictly', () async {
    final h = Harness();
    await h.enroll();
    final p = (await h.prepare(125000)).payload;
    expect(p.amountCents, 125000);
    expect(p.tier, RiskTier.b);
    expect(p.deviceKey, h.server.devices.single.deviceKey.fingerprint);
    final json = jsonDecode(p.canonicalText) as Map<String, dynamic>;
    expect(json.keys.toSet(), TransactionPayload.fieldNames);
  });
}
