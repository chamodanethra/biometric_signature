/// Supported signature algorithms on iOS.
enum IOSSignatureType { RSA, ECDSA }

/// Convenience helpers for [IOSSignatureType].
extension IOSSignatureTypeExtension on IOSSignatureType {
  /// Returns `true` when the ECDSA algorithm is selected.
  bool get isEc => this == IOSSignatureType.ECDSA;
}

/// iOS-specific configuration for enrolling or using biometric keys.
class IosConfig {
  /// Whether device credentials (passcode) can unlock the key instead of
  /// biometrics.
  bool useDeviceCredentials;

  /// Key algorithm to use when creating a signature.
  IOSSignatureType signatureType;

  /// Creates a new iOS configuration.
  IosConfig({
    required this.useDeviceCredentials,
    this.signatureType = IOSSignatureType.RSA,
  });
}
