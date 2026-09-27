import 'package:biometric_signature/biometric_signature.dart';

import '../platform/device_platform.dart';

/// A display label for an `authenticationType` result.
class AuthTypeLabel {
  /// Creates a label.
  const AuthTypeLabel(this.label, this.reliability);

  /// What was used, e.g. `Biometric`.
  final String label;

  /// How far to trust it on this platform.
  final String reliability;

  @override
  String toString() => '$label ($reliability)';
}

/// Describes [type] as reported on [platform].
///
/// [silentKey] marks keys created with `requireAuthentication: false`,
/// which never prompt and therefore report `unknown`.
AuthTypeLabel describeAuthenticationType(
  AuthenticationType? type, {
  required DevicePlatform platform,
  bool silentKey = false,
}) {
  if (silentKey && platform != DevicePlatform.windows) {
    return const AuthTypeLabel(
      'No user authentication (silent key)',
      'The key was created with requireAuthentication: false, so it proves '
          'possession of the device only.',
    );
  }
  final label = switch (type) {
    AuthenticationType.biometric => 'Biometric',
    AuthenticationType.credential => 'Device credential (PIN / passcode)',
    AuthenticationType.unknown || null => 'Unknown',
  };
  final reliability =
      switch (PlatformCapabilities.of(platform).authTypeReliability) {
    AuthTypeReliability.authoritative =>
      'Reported by Android. Still a client claim: the server cannot verify '
          'it; rely on the attested key policy instead.',
    AuthTypeReliability.inferred =>
      'Inferred by the plugin from the prompt policy on Apple platforms, '
          'not reported by the OS.',
    AuthTypeReliability.notReported =>
      'Windows Hello does not report the method; always unknown.',
  };
  return AuthTypeLabel(label, reliability);
}
