/// The composition root: the plugin, the mock network, the bank and the
/// client-side services, wired together.
library;

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/widgets.dart';

import 'client/approval_service.dart';
import 'client/bank_client.dart';
import 'client/key_setup.dart';
import 'client/session.dart';
import 'server/bank_server.dart';
import 'server/models.dart';
import 'shared_prefs_store.dart';

/// Everything the screens need.
class AppServices {
  AppServices._({
    required this.api,
    required this.platform,
    required this.transport,
    required this.serverClock,
    required this.clientClock,
    required this.server,
    required this.client,
    required this.keys,
    required this.approvals,
    required this.session,
    required this.clientStore,
  });

  /// Wires the app. Defaults are for the real app: the plugin, the running
  /// platform, SharedPreferences stores under `server.` and `client.`,
  /// system clocks, simulated latency and Google's attestation roots.
  /// Tests pass the fake platform, in-memory stores and a manual clock.
  factory AppServices.create({
    BiometricSignature? api,
    DevicePlatform? platform,
    KeyValueStore? serverStore,
    KeyValueStore? clientStore,
    Clock? serverClock,
    Clock? clientClock,
    Duration latency = const Duration(milliseconds: 200),
    Set<String>? trustedRootSpkiSha256,
    bool verifyAttestationInIsolate = true,
  }) {
    final plugin = api ?? BiometricSignature();
    final devicePlatform = platform ?? currentDevicePlatform();
    final bankClock = serverClock ?? Clock();
    final deviceClock = clientClock ?? Clock();
    final transport = MockTransport(latency: latency, clock: bankClock);
    final server = BankServer(
      transport: transport,
      store: serverStore ?? SharedPrefsKeyValueStore('server.'),
      clock: bankClock,
      trustedRootSpkiSha256: trustedRootSpkiSha256,
      verifyAttestationInIsolate: verifyAttestationInIsolate,
    );
    final client =
        BankClient(api: plugin, transport: transport, clock: deviceClock);
    final store = clientStore ?? SharedPrefsKeyValueStore('client.');
    return AppServices._(
      api: plugin,
      platform: devicePlatform,
      transport: transport,
      serverClock: bankClock,
      clientClock: deviceClock,
      server: server,
      client: client,
      keys: KeySetup(api: plugin, platform: devicePlatform),
      approvals: ApprovalService(api: plugin, client: client),
      session: BankSession(
          api: plugin, client: client, store: store, platform: devicePlatform),
      clientStore: store,
    );
  }

  /// The plugin.
  final BiometricSignature api;

  /// The running (or simulated) platform.
  final DevicePlatform platform;

  /// The in-process network between app and bank.
  final MockTransport transport;

  /// The bank's clock.
  final Clock serverClock;

  /// The device's clock (skewable from the console).
  final Clock clientClock;

  /// The mock bank.
  final BankServer server;

  /// The bank API client.
  final BankClient client;

  /// Key creation.
  final KeySetup keys;

  /// Transfer approval.
  final ApprovalService approvals;

  /// Client state.
  final BankSession session;

  /// Client persistence.
  final KeyValueStore clientStore;

  /// Root navigator (to unwind after a reset).
  final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

  /// Platform capabilities.
  PlatformCapabilities get capabilities => PlatformCapabilities.of(platform);

  /// Loads the bank and the client state.
  Future<void> start() async {
    await server.load();
    await session.bootstrap();
  }

  /// Deletes every key (`deleteAllKeys`), clears both stores and reseeds
  /// the bank.
  Future<void> resetDemo() async {
    await api.deleteAllKeys();
    transport
      ..clearFaults()
      ..log.clear();
    client.reset();
    clientClock.skew = Duration.zero;
    await clientStore.clear();
    await server.reset();
    await session.forget(
        reason: 'Demo reset: every key was deleted with deleteAllKeys() and '
            'the bank forgot this device.');
    navigatorKey.currentState?.popUntil((route) => route.isFirst);
  }

  /// Revokes this device at the bank, then deletes both keys.
  ///
  /// Throws `BankError` if the bank cannot be reached; the keys are kept
  /// in that case so the user can retry.
  Future<void> unbindDevice() async {
    await client.unbind();
    await api.deleteKeys(keyAlias: KeyAliases.approval);
    await api.deleteKeys(keyAlias: KeyAliases.deviceBinding);
    client.reset();
    await session.forget(
        reason: 'This device was unbound: the bank revoked it and both keys '
            'were deleted.');
    navigatorKey.currentState?.popUntil((route) => route.isFirst);
  }
}
