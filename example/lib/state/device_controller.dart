import 'package:biometric_signature/biometric_signature.dart';

import 'controller_base.dart';

/// Device screen: `biometricAuthAvailable` and `isDeviceLockSet`.
class DeviceController extends ExplorerController {
  /// Creates the controller.
  DeviceController(super.state);

  /// Operation id for [checkAvailability].
  static const String availabilityOp = 'availability';

  /// Operation id for [checkDeviceLock].
  static const String lockOp = 'deviceLock';

  /// Last `biometricAuthAvailable` result.
  BiometricAvailability? availability;

  /// Last `isDeviceLockSet` result.
  bool? deviceLockSet;

  /// Calls `biometricAuthAvailable`.
  Future<void> checkAvailability() => run(availabilityOp, () async {
        availability = await api.biometricAuthAvailable();
      });

  /// Calls `isDeviceLockSet`.
  Future<void> checkDeviceLock() => run(lockOp, () async {
        deviceLockSet = await api.isDeviceLockSet();
      });

  /// Runs both checks (on launch and from the refresh button).
  Future<void> refresh() async {
    await checkAvailability();
    await checkDeviceLock();
  }
}
