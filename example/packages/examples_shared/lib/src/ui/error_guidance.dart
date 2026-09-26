import 'package:biometric_signature/biometric_signature.dart';

import '../platform/device_platform.dart';

/// What the app (or user) should do about an error.
enum RecoveryAction {
  /// Nothing to do.
  none,

  /// Try the same operation again.
  retry,

  /// Try again after a short wait.
  retryLater,

  /// Enroll a fingerprint or face in system settings.
  enrollBiometrics,

  /// Set a device PIN, pattern, password or passcode.
  setDeviceLock,

  /// Delete the key and register a new one (and its public key).
  recreateKey,

  /// Authenticate with the device credential first.
  useDeviceCredential,

  /// Install a system update.
  updateOs,

  /// Use or delete the existing key, or pick another alias.
  chooseDifferentAlias,

  /// Fix the request (a bug in the calling code).
  fixInput,

  /// The device cannot do this; offer an alternative.
  unsupportedOnDevice,
}

/// User-facing guidance for a [BiometricError].
class ErrorGuidance {
  /// Creates guidance.
  const ErrorGuidance({
    required this.code,
    required this.title,
    required this.message,
    required this.action,
    required this.isTransient,
    required this.emittedOn,
  });

  /// The error code.
  final BiometricError code;

  /// Short title.
  final String title;

  /// What happened and what to do, in plain language.
  final String message;

  /// Suggested recovery.
  final RecoveryAction action;

  /// Whether retrying the same operation later can succeed.
  final bool isTransient;

  /// Platforms whose native code can return this code.
  final Set<DevicePlatform> emittedOn;
}

const _all = {
  DevicePlatform.android,
  DevicePlatform.ios,
  DevicePlatform.macos,
  DevicePlatform.windows,
};
const _mobileAndMac = {
  DevicePlatform.android,
  DevicePlatform.ios,
  DevicePlatform.macos,
};

/// Guidance for [code]; `null` is treated as [BiometricError.unknown].
///
/// The switch is exhaustive with no default, so adding a value to
/// [BiometricError] breaks the build until it is handled here.
ErrorGuidance guidanceFor(BiometricError? code) {
  final c = code ?? BiometricError.unknown;
  switch (c) {
    case BiometricError.success:
      return ErrorGuidance(
        code: c,
        title: 'Done',
        message: 'The operation completed successfully.',
        action: RecoveryAction.none,
        isTransient: false,
        emittedOn: _all,
      );
    case BiometricError.userCanceled:
      return ErrorGuidance(
        code: c,
        title: 'Cancelled',
        message: 'You closed the prompt. Nothing was changed — try again '
            'when you are ready.',
        action: RecoveryAction.retry,
        isTransient: true,
        emittedOn: _all,
      );
    case BiometricError.notAvailable:
      return ErrorGuidance(
        code: c,
        title: 'Biometrics unavailable',
        message: 'Biometric authentication is not available right now: the '
            'sensor may be missing, busy or disabled. For key attestation it '
            'can also mean the keystore is not ready yet — retry later with '
            'a fresh challenge. On Windows, decryption always reports this.',
        action: RecoveryAction.retryLater,
        isTransient: true,
        emittedOn: _all,
      );
    case BiometricError.notEnrolled:
      return ErrorGuidance(
        code: c,
        title: 'No biometrics enrolled',
        message: 'Add a fingerprint or face in system Settings, then try '
            'again.',
        action: RecoveryAction.enrollBiometrics,
        isTransient: false,
        emittedOn: _mobileAndMac,
      );
    case BiometricError.lockedOut:
      return ErrorGuidance(
        code: c,
        title: 'Too many attempts',
        message: 'Biometrics are locked after too many failed attempts. On '
            'Android, wait about 30 seconds. On iPhone, iPad and Mac, Face '
            'ID / Touch ID stays locked until you enter your passcode.',
        action: RecoveryAction.retryLater,
        isTransient: true,
        emittedOn: _all,
      );
    case BiometricError.lockedOutPermanent:
      return ErrorGuidance(
        code: c,
        title: 'Biometrics locked',
        message: 'Biometrics stay locked until you unlock with your device '
            'PIN, pattern or password. Unlock with the device credential '
            'first, then try again.',
        action: RecoveryAction.useDeviceCredential,
        isTransient: false,
        emittedOn: {DevicePlatform.android},
      );
    case BiometricError.keyNotFound:
      return ErrorGuidance(
        code: c,
        title: 'Key not found',
        message: 'There is no key under this alias on this device: it was '
            'never created, was deleted, or did not survive a reinstall or '
            'backup restore. Register this device again.',
        action: RecoveryAction.recreateKey,
        isTransient: false,
        emittedOn: _all,
      );
    case BiometricError.keyInvalidated:
      return ErrorGuidance(
        code: c,
        title: 'Key invalidated',
        message: 'A fingerprint or face was added or removed, so this key '
            'can never be used again. Delete it and register again.',
        action: RecoveryAction.recreateKey,
        isTransient: false,
        emittedOn: _mobileAndMac,
      );
    case BiometricError.unknown:
      return ErrorGuidance(
        code: c,
        title: 'Something went wrong',
        message: 'The platform reported an unexpected error. Try again; if '
            'it keeps happening, check the key with getKeyInfo(checkValidity: '
            'true).',
        action: RecoveryAction.retry,
        isTransient: false,
        emittedOn: _all,
      );
    case BiometricError.invalidInput:
      return ErrorGuidance(
        code: c,
        title: 'Invalid request',
        message: 'The request was rejected before any prompt — for example '
            'a payload that is not valid base64 or hex, or an attestation '
            'challenge outside 1–128 bytes.',
        action: RecoveryAction.fixInput,
        isTransient: false,
        emittedOn: _all,
      );
    case BiometricError.securityUpdateRequired:
      return ErrorGuidance(
        code: c,
        title: 'Security update required',
        message: 'The biometric sensor has a known vulnerability. Install '
            'the latest system update, then try again.',
        action: RecoveryAction.updateOs,
        isTransient: false,
        emittedOn: {DevicePlatform.android},
      );
    case BiometricError.notSupported:
      return ErrorGuidance(
        code: c,
        title: 'Not supported',
        message: 'This device or OS version cannot do this — for example '
            'key attestation on iOS, macOS, Windows or Android 6, or a '
            'keystore that cannot attest keys.',
        action: RecoveryAction.unsupportedOnDevice,
        isTransient: false,
        emittedOn: _all,
      );
    case BiometricError.systemCanceled:
      return ErrorGuidance(
        code: c,
        title: 'Interrupted',
        message: 'The system closed the prompt, for example because the app '
            'went to the background. Try again.',
        action: RecoveryAction.retry,
        isTransient: true,
        emittedOn: _mobileAndMac,
      );
    case BiometricError.promptError:
      return ErrorGuidance(
        code: c,
        title: 'Prompt could not be shown',
        message: 'The biometric prompt failed to appear. Bring the app to '
            'the foreground and try again.',
        action: RecoveryAction.retry,
        isTransient: true,
        emittedOn: _mobileAndMac,
      );
    case BiometricError.keyAlreadyExists:
      return ErrorGuidance(
        code: c,
        title: 'Key already exists',
        message: 'A key already exists under this alias and failIfExists was '
            'set, so it was kept. Use it, delete it first, or choose '
            'another alias.',
        action: RecoveryAction.chooseDifferentAlias,
        isTransient: false,
        emittedOn: _all,
      );
    case BiometricError.passcodeNotSet:
      return ErrorGuidance(
        code: c,
        title: 'No screen lock',
        message: 'Set a device PIN, pattern, password or passcode in system '
            'Settings. Hardware-backed keys and biometrics require one.',
        action: RecoveryAction.setDeviceLock,
        isTransient: false,
        emittedOn: _mobileAndMac,
      );
    case BiometricError.authenticationFailed:
      return ErrorGuidance(
        code: c,
        title: 'Not recognized',
        message: 'Your fingerprint or face was not recognized. The key is '
            'fine — try again.',
        action: RecoveryAction.retry,
        isTransient: true,
        emittedOn: _mobileAndMac,
      );
    case BiometricError.notInteractive:
      return ErrorGuidance(
        code: c,
        title: 'Prompt not allowed right now',
        message: 'The prompt cannot be shown while the app is in the '
            'background. Try again once the app is in the foreground.',
        action: RecoveryAction.retry,
        isTransient: true,
        emittedOn: _mobileAndMac,
      );
  }
}
