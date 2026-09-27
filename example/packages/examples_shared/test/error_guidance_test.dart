import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('every BiometricError has non-empty guidance', () {
    expect(BiometricError.values, hasLength(18));
    for (final code in BiometricError.values) {
      final g = guidanceFor(code);
      expect(g.code, code);
      expect(g.title.trim(), isNotEmpty, reason: code.name);
      expect(g.message.trim(), isNotEmpty, reason: code.name);
      expect(g.emittedOn, isNotEmpty, reason: code.name);
      expect(g.emittedOn, isNot(contains(DevicePlatform.other)));
      if (code != BiometricError.success) {
        expect(g.action, isNot(RecoveryAction.none), reason: code.name);
        expect(recoveryActionLabel(g.action), isNotNull, reason: code.name);
      }
    }
  });

  test('null is treated as unknown', () {
    expect(guidanceFor(null).code, BiometricError.unknown);
  });

  test('key lifecycle errors point to re-registration', () {
    final invalidated = guidanceFor(BiometricError.keyInvalidated);
    expect(invalidated.action, RecoveryAction.recreateKey);
    expect(invalidated.message, contains('never be used again'));
    expect(invalidated.emittedOn,
        {DevicePlatform.android, DevicePlatform.ios, DevicePlatform.macos});
    final missing = guidanceFor(BiometricError.keyNotFound);
    expect(missing.action, RecoveryAction.recreateKey);
    expect(missing.emittedOn, contains(DevicePlatform.windows));
    expect(guidanceFor(BiometricError.lockedOutPermanent).action,
        RecoveryAction.useDeviceCredential);
    expect(guidanceFor(BiometricError.userCanceled).isTransient, isTrue);
  });

  test('platform capabilities', () {
    final windows = PlatformCapabilities.of(DevicePlatform.windows);
    expect(windows.supportsEcKeys, isFalse);
    expect(windows.supportsDecrypt, isFalse);
    expect(windows.silentKeysPrompt, isTrue);
    expect(windows.supportsSilentKeys, isFalse);
    expect(windows.authTypeReliability, AuthTypeReliability.notReported);
    final android = PlatformCapabilities.of(DevicePlatform.android);
    expect(android.supportsAttestation, isTrue);
    expect(android.authTypeReliability, AuthTypeReliability.authoritative);
    for (final apple in [DevicePlatform.ios, DevicePlatform.macos]) {
      final c = PlatformCapabilities.of(apple);
      expect(c.supportsAttestation, isFalse);
      expect(c.supportsDecrypt, isTrue);
      expect(c.authTypeReliability, AuthTypeReliability.inferred);
    }
    for (final p in DevicePlatform.values) {
      expect(PlatformCapabilities.of(p).notes, isNotEmpty);
    }
  });

  test('current platform follows defaultTargetPlatform and overrides', () {
    debugDefaultTargetPlatformOverride = TargetPlatform.windows;
    expect(currentDevicePlatform(), DevicePlatform.windows);
    debugDevicePlatformOverride = DevicePlatform.ios;
    expect(currentDevicePlatform(), DevicePlatform.ios);
    debugDevicePlatformOverride = null;
    debugDefaultTargetPlatformOverride = null;
    expect(devicePlatformFor(TargetPlatform.linux), DevicePlatform.other);
  });

  test('authentication type labels', () {
    expect(
        describeAuthenticationType(AuthenticationType.biometric,
                platform: DevicePlatform.android)
            .label,
        'Biometric');
    expect(
        describeAuthenticationType(AuthenticationType.unknown,
                platform: DevicePlatform.android, silentKey: true)
            .label,
        contains('silent key'));
    expect(
        describeAuthenticationType(null, platform: DevicePlatform.windows)
            .reliability,
        contains('always unknown'));
    expect(
        describeAuthenticationType(AuthenticationType.credential,
                platform: DevicePlatform.ios)
            .reliability,
        contains('Inferred'));
  });
}
