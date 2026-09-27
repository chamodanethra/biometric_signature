import 'package:banking_app_example/client/approval_service.dart';
import 'package:banking_app_example/client/bank_client.dart';
import 'package:banking_app_example/client/key_setup.dart';
import 'package:banking_app_example/server/bank_server.dart';
import 'package:banking_app_example/services.dart';
import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/biometric_signature_platform_interface.dart'
    show BiometricSignaturePlatform;
import 'package:examples_shared/server.dart';
import 'package:examples_shared/testing.dart';
import 'package:examples_shared/ui.dart';

/// The app wired to the software fake of the plugin, in-memory stores, a
/// manual clock (shared by bank and device), zero latency and the fake's
/// synthetic attestation root.
class Harness {
  Harness({
    DevicePlatform platform = DevicePlatform.android,
    AuthenticationType authenticationType = AuthenticationType.biometric,
  })  : fake = SoftwareBiometricPlatform(
          simulatedPlatform: platform,
          authenticationTypeToReport: authenticationType,
          attestedPackageName: BankServer.androidPackageName,
        ),
        clock = ManualClock(DateTime.utc(2026, 9, 27, 12)) {
    BiometricSignaturePlatform.instance = fake;
    debugDevicePlatformOverride = platform;
    deviceClock = Clock(source: clock.now);
    services = AppServices.create(
      api: BiometricSignature(),
      platform: platform,
      serverStore: InMemoryKeyValueStore(),
      clientStore: InMemoryKeyValueStore(),
      serverClock: clock,
      clientClock: deviceClock,
      latency: Duration.zero,
      trustedRootSpkiSha256: {fake.syntheticRootSpkiSha256},
      verifyAttestationInIsolate: false,
    );
  }

  /// The fake plugin platform.
  final SoftwareBiometricPlatform fake;

  /// The bank's clock (the device clock follows it, plus its own skew).
  final ManualClock clock;

  /// The device clock.
  late final Clock deviceClock;

  /// The app.
  late final AppServices services;

  BankServer get server => services.server;
  BankClient get client => services.client;

  /// Starts the app and binds the device.
  Future<KeyRegistrationResult> enroll({bool allowPin = false}) async {
    await services.start();
    final attempt =
        DeviceEnrollment(keys: services.keys, client: services.client);
    final start = await attempt.begin();
    final code = server.outbox.latestFor(start.enrollmentId)!.code;
    final result =
        await attempt.complete(otp: code, allowDeviceCredential: allowPin);
    await services.session.completeEnrollment(result,
        attempt: attempt, allowDeviceCredential: allowPin);
    return result;
  }

  /// Prepares a transfer from checking.
  Future<PreparedTransfer> prepare(int cents, {String payeeId = 'p-alice'}) =>
      client.prepareTransfer(
          fromAccount: 'CHK-4821', payeeId: payeeId, amountCents: cents);

  /// Approves [prepared] the way the approve screen does.
  Future<ApprovalOutcome> approve(PreparedTransfer prepared) =>
      services.approvals.approve(prepared,
          allowDeviceCredential:
              services.session.enrollment?.allowDeviceCredential ?? false);

  /// Prepares and approves; expects the approval to be submitted.
  Future<ConfirmResult> transfer(int cents) async {
    final outcome = await approve(await prepare(cents));
    if (outcome is! ApprovalSubmitted) {
      throw StateError('Expected ApprovalSubmitted, got $outcome');
    }
    return outcome.result;
  }

  /// Checking balance, according to the bank.
  int get checkingBalance => server.ledger.account('CHK-4821')!.balanceCents;

  /// Resets global overrides.
  static void tearDown() {
    debugDevicePlatformOverride = null;
  }
}
