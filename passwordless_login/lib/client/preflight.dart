import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';

/// What the device can do before any key is created.
class PreflightResult {
  /// Creates a result.
  const PreflightResult({
    required this.platform,
    required this.availability,
    required this.deviceLockSet,
    required this.issues,
  });

  /// The running platform.
  final DevicePlatform platform;

  /// `biometricAuthAvailable()`.
  final BiometricAvailability availability;

  /// `isDeviceLockSet()` (Windows: whether Windows Hello is set up).
  final bool deviceLockSet;

  /// Problems that stop registration, with guidance.
  final List<ErrorGuidance> issues;

  /// Whether a biometric-bound key can be created.
  bool get ready => issues.isEmpty;

  /// What the platform can do.
  PlatformCapabilities get capabilities => PlatformCapabilities.of(platform);
}

/// Checks screen lock and biometric enrollment up front, so the user is
/// sent to Settings before a key is created rather than after a failure.
///
/// Registration uses `enforceBiometric: true`, so both are required. The
/// same problems still surface reactively as `passcodeNotSet` and
/// `notEnrolled` from `createKeys` (e.g. on iOS, where `isDeviceLockSet`
/// returns `true` when it cannot tell).
Future<PreflightResult> runPreflight(
    BiometricSignature api, DevicePlatform platform) async {
  final availability = await api.biometricAuthAvailable();
  final lockSet = await api.isDeviceLockSet();
  final codes = <BiometricError>{
    if (!lockSet)
      platform == DevicePlatform.windows
          ? BiometricError.notAvailable
          : BiometricError.passcodeNotSet,
    if (platform != DevicePlatform.windows &&
        availability.hasEnrolledBiometrics == false)
      BiometricError.notEnrolled
    else if (availability.canAuthenticate == false)
      BiometricError.notAvailable,
  };
  final issues = [for (final c in codes) guidanceFor(c)];
  return PreflightResult(
    platform: platform,
    availability: availability,
    deviceLockSet: lockSet,
    issues: issues,
  );
}
