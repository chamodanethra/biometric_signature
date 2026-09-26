import 'package:biometric_signature/biometric_signature_platform_interface.dart'
    show BiometricSignaturePlatform;
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/testing.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secure_vault_example/client/vault_controller.dart';
import 'package:secure_vault_example/models/vault_key_record.dart';
import 'package:secure_vault_example/services.dart';

/// One simulated device: a software fake of the plugin for [platform],
/// in-memory stores, its own provisioning server and a controller.
///
/// The plugin API routes through the global
/// `BiometricSignaturePlatform.instance`; call [use] before acting as this
/// device when a test has several.
class TestDevice {
  /// Creates the device (not started).
  TestDevice(this.platform)
      : fake = SoftwareBiometricPlatform(simulatedPlatform: platform),
        services = AppServices.inMemory(platform: platform) {
    controller = VaultController(services);
  }

  /// Creates and starts a device.
  static Future<TestDevice> start(DevicePlatform platform) async {
    final device = TestDevice(platform);
    device.use();
    await device.controller.start();
    return device;
  }

  /// Simulated platform.
  final DevicePlatform platform;

  /// The plugin fake.
  final SoftwareBiometricPlatform fake;

  /// Server, network and storage.
  final AppServices services;

  /// App state.
  late final VaultController controller;

  /// Makes this device's fake the active plugin platform.
  void use() => BiometricSignaturePlatform.instance = fake;

  /// Provisions a vault key and expects success.
  Future<Provisioned> provision(VaultKeyChoice choice,
      {bool useDeviceCredentials = false}) async {
    use();
    final outcome = await controller.provision(
      choice: choice,
      useDeviceCredentials: useDeviceCredentials,
    );
    expect(outcome, isA<Provisioned>());
    final provisioned = outcome as Provisioned;
    expect(provisioned.syncError, isNull);
    return provisioned;
  }

  /// Number of calls the fake received for [method].
  int callCount(String method) =>
      fake.calls.where((c) => c.method == method).length;
}

/// Restores the real plugin platform after each test.
void restorePluginPlatformAfterEachTest() {
  late BiometricSignaturePlatform original;
  setUp(() => original = BiometricSignaturePlatform.instance);
  tearDown(() => BiometricSignaturePlatform.instance = original);
}
