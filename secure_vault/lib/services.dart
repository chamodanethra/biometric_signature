import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/ui.dart';

import 'client/provisioning_client.dart';
import 'client/vault_repository.dart';
import 'server/in_transit_tamper.dart';
import 'server/provisioning_server.dart';
import 'shared_prefs_store.dart';

/// Wires the plugin, the in-process provisioning server, the mock network
/// and the device-side storage together.
class AppServices {
  /// Creates the services. Use [AppServices.device] in the app and
  /// [AppServices.inMemory] in tests.
  AppServices({
    required this.api,
    required this.platform,
    required KeyValueStore serverStore,
    required KeyValueStore clientStore,
    Duration latency = const Duration(milliseconds: 150),
  })  : transport = MockTransport(latency: latency),
        tamper = InTransitTamper(),
        repository = VaultRepository(clientStore) {
    server = ProvisioningServer(
      transport: transport,
      store: serverStore,
      tamper: tamper,
    );
    client = ProvisioningClient(transport);
  }

  /// The real plugin, SharedPreferences-backed stores (`server.` and
  /// `client.` prefixes) and simulated network latency.
  factory AppServices.device() => AppServices(
        api: BiometricSignature(),
        platform: currentDevicePlatform(),
        serverStore: SharedPrefsKeyValueStore('server.'),
        clientStore: SharedPrefsKeyValueStore('client.'),
      );

  /// In-memory stores and no latency, for tests. Install a fake plugin
  /// platform (`BiometricSignaturePlatform.instance`) separately.
  factory AppServices.inMemory({required DevicePlatform platform}) =>
      AppServices(
        api: BiometricSignature(),
        platform: platform,
        serverStore: InMemoryKeyValueStore(),
        clientStore: InMemoryKeyValueStore(),
        latency: Duration.zero,
      );

  /// The plugin.
  final BiometricSignature api;

  /// The platform this runs on (decides the encryption scheme).
  final DevicePlatform platform;

  /// The mock network, with its wire log and faults.
  final MockTransport transport;

  /// Simulated attacker on server → device deliveries.
  final InTransitTamper tamper;

  /// Device-side storage.
  final VaultRepository repository;

  /// The provisioning server.
  late final ProvisioningServer server;

  /// The device's client for the server.
  late final ProvisioningClient client;

  /// Starts the server and loads the device's storage.
  Future<void> start() async {
    await server.start();
    await repository.load();
  }

  /// Clears both sides' storage, the wire log and pending faults.
  Future<void> resetStores() async {
    transport.clearFaults();
    transport.log.clear();
    tamper.reset();
    await server.reset();
    await repository.clear();
  }
}
