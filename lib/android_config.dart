/// Android-specific configuration for enrolling or using biometric keys.
class AndroidConfig {
  /// Whether device credentials (PIN/pattern/password) can unlock the key
  /// instead of biometrics.
  bool useDeviceCredentials;

  /// Key algorithm to use when creating a signature.
  AndroidSignatureType signatureType;

  /// Creates a new Android configuration.
  AndroidConfig({
    required this.useDeviceCredentials,
    this.signatureType = AndroidSignatureType.RSA,
  });
}

/// Supported signature algorithms on Android.
enum AndroidSignatureType { RSA, ECDSA }

/// Convenience helpers for [AndroidSignatureType].
extension AndroidSignatureTypeExtension on AndroidSignatureType {
  /// Returns `true` when the ECDSA algorithm is selected.
  bool get isEc => this == AndroidSignatureType.ECDSA;
}