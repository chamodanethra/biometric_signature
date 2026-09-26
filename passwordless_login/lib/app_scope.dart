import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/widgets.dart';

import 'client/accounts.dart';
import 'client/auth_client.dart';
import 'server/auth_server.dart';

/// Everything the app wires together: the plugin, the in-process mock
/// server behind its transport, and the client.
class AppServices {
  /// Creates the services. Prefer [create].
  AppServices({
    required this.api,
    required this.platform,
    required this.serverClock,
    required this.transport,
    required this.server,
    required this.accounts,
    required this.client,
  });

  /// Builds and loads the services.
  ///
  /// The app uses the defaults: SharedPreferences under `server.` and
  /// `client.`, 150 ms simulated latency, Google's attestation roots, and
  /// verification on a background isolate. Tests pass in-memory stores,
  /// zero latency, the fake platform's synthetic root and
  /// `verifyInIsolate: false`.
  static Future<AppServices> create({
    BiometricSignature? api,
    DevicePlatform? platform,
    KeyValueStore? serverStore,
    KeyValueStore? clientStore,
    Clock? serverClock,
    Duration latency = const Duration(milliseconds: 150),
    Set<String>? trustedRootSpkiSha256,
    bool verifyInIsolate = true,
  }) async {
    final clock = serverClock ?? Clock();
    final transport = MockTransport(latency: latency, clock: clock);
    final server = AuthServer(
      store: serverStore ?? SharedPrefsKeyValueStore('server.'),
      transport: transport,
      clock: clock,
      trustedRootSpkiSha256: trustedRootSpkiSha256,
      verifyInIsolate: verifyInIsolate,
    );
    final accounts =
        AccountRepository(clientStore ?? SharedPrefsKeyValueStore('client.'));
    final plugin = api ?? BiometricSignature();
    final devicePlatform = platform ?? currentDevicePlatform();
    await server.load();
    await accounts.load();
    return AppServices(
      api: plugin,
      platform: devicePlatform,
      serverClock: clock,
      transport: transport,
      server: server,
      accounts: accounts,
      client: AuthClient(
        api: plugin,
        transport: transport,
        accounts: accounts,
        platform: devicePlatform,
      ),
    );
  }

  /// The plugin.
  final BiometricSignature api;

  /// The running platform.
  final DevicePlatform platform;

  /// The mock server's clock.
  final Clock serverClock;

  /// The in-process wire.
  final MockTransport transport;

  /// The mock server.
  final AuthServer server;

  /// Accounts on this device.
  final AccountRepository accounts;

  /// The client.
  final AuthClient client;

  /// What the platform can do.
  PlatformCapabilities get capabilities => PlatformCapabilities.of(platform);

  /// Deletes every key (`deleteAllKeys`) and clears both the server's and
  /// the client's stores, the wire log and pending faults.
  Future<void> resetDemo() async {
    await api.deleteAllKeys();
    await server.reset();
    await accounts.clearAll();
    transport
      ..clearFaults()
      ..log.clear();
  }
}

/// Makes [AppServices] available to the widget tree.
class AppScope extends InheritedWidget {
  /// Creates the scope.
  const AppScope({super.key, required this.services, required super.child});

  /// The services.
  final AppServices services;

  /// The nearest services.
  static AppServices of(BuildContext context) {
    final scope = context.dependOnInheritedWidgetOfExactType<AppScope>();
    assert(scope != null, 'No AppScope above this context');
    return scope!.services;
  }

  @override
  bool updateShouldNotify(AppScope oldWidget) => services != oldWidget.services;
}
