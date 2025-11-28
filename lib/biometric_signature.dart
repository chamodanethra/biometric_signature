import 'android_config.dart';
import 'biometric_signature_platform_interface.dart';
import 'decryption_options.dart';
import 'ios_config.dart';
import 'key_material.dart';
import 'signature_options.dart';

export 'android_config.dart';
export 'decryption_options.dart';
export 'ios_config.dart';
export 'key_material.dart';
export 'signature_options.dart';

/// High-level API for interacting with the Biometric Signature plugin.
///
/// This class provides a uniform Flutter interface over platform-specific
/// hardware-backed signing and secure decryption workflows. When supported,
/// keys are always created inside secure hardware:
///
/// - **Android**: Android Keystore / StrongBox
/// - **iOS**: Secure Enclave
///
/// Hybrid modes are used automatically when hardware keys cannot perform the
/// required decryption operation (for example, ECIES on Android or RSA PKCS#1
/// decryption on iOS).
class BiometricSignature {
  /// Creates a new biometric-protected key pair used for signing
  /// (and optionally decryption, depending on the platform and configuration).
  ///
  /// ## Key Modes
  ///
  /// The plugin automatically selects the appropriate mode:
  ///
  /// - **RSA Mode**
  ///   Hardware RSA-2048 key pair supporting SHA256withRSA signatures.
  ///   Optional RSA/PKCS#1 decryption when enabled. Private key never leaves
  ///   secure hardware.
  ///
  /// - **EC Signing-Only**
  ///   Hardware-backed P-256 EC key pair supporting ECDSA signatures only.
  ///   Decryption is not supported in this mode.
  ///
  /// - **Hybrid EC Mode**
  ///   Used when EC signing is required but the platform cannot perform ECIES
  ///   decryption inside hardware.
  ///
  ///   - **Android**
  ///     Hardware EC signing key + software EC key for ECIES decryption.
  ///     The software EC private key is encrypted using a biometric-protected
  ///     AES-256 master key (stored in Keystore/StrongBox). The wrapped key
  ///     itself is stored in app-private files with MODE_PRIVATE permissions.
  ///
  ///   - **iOS**
  ///     Hardware EC signing key + software RSA private key for PKCS#1
  ///     decryption. The software RSA key is encrypted using ECIES with
  ///     Secure Enclave EC public key material and stored in Keychain.
  ///
  /// The returned [KeyCreationResult] includes the public key in the requested
  /// output format.
  Future<KeyCreationResult?> createKeys({
    AndroidConfig? androidConfig,
    IosConfig? iosConfig,
    KeyFormat keyFormat = KeyFormat.base64,
    bool setInvalidatedByBiometricEnrollment = true,
    bool enforceBiometric = false,
  }) async {
    final response = await BiometricSignaturePlatform.instance.createKeys(
      androidConfig ??
          AndroidConfig(
            useDeviceCredentials: false,
            setInvalidatedByBiometricEnrollment: true,
          ),
      iosConfig ??
          IosConfig(useDeviceCredentials: false, biometryCurrentSet: true),
      keyFormat: keyFormat,
      enforceBiometric: enforceBiometric,
    );

    return response == null ? null : KeyCreationResult.fromChannel(response);
  }

  /// Creates a digital signature using biometric authentication.
  ///
  /// ## Algorithms
  ///
  /// - **RSA**: SHA256withRSA (PKCS#1 v1.5)
  /// - **EC**:
  ///   - Android: SHA256withECDSA
  ///   - iOS: ecdsaSignatureMessageX962SHA256 (ANSI X9.62 format)
  ///
  /// Hybrid EC mode always uses the hardware EC signing key.
  ///
  /// The returned [SignatureResult] contains both the signature and the
  /// corresponding public key in the requested format.
  Future<SignatureResult?> createSignature(SignatureOptions options) async {
    final response = await BiometricSignaturePlatform.instance.createSignature(
      options,
    );
    return response == null ? null : SignatureResult.fromChannel(response);
  }

  /// Decrypts a Base64-encoded payload using biometric authentication.
  ///
  /// ## Supported Algorithms
  ///
  /// - **RSA**
  ///   RSA/ECB/PKCS1Padding (Android and iOS hybrid mode).
  ///
  ///   - **ECIES**
  ///   P-256 ECIES using ECDH → X9.63 KDF (SHA-256) → AES-128-GCM.
  ///
  ///   - **Android**
  ///     Manual ECIES implementation (ECDH → X9.63 KDF → AES-GCM).
  ///     The wrapped software EC private key is read from app-private file storage
  ///     and unwrapped using a biometric-protected AES-256 master key from Keystore/StrongBox.
  ///     All sensitive key material is zeroized immediately after use.
  ///
  ///   - **iOS**
  ///     Native ECIES using `SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM`.
  ///     EC-only mode uses direct ECIES decryption; hybrid mode unwraps the RSA key
  ///     from Keychain before performing RSA decryption.
  Future<DecryptResult?> decrypt(DecryptionOptions options) async {
    final response = await BiometricSignaturePlatform.instance.decrypt(options);
    return response == null ? null : DecryptResult.fromChannel(response);
  }

  /// Deletes all active biometric key material.
  ///
  /// - Hardware keys (RSA or EC): removed from Keystore / Secure Enclave.
  /// - Hybrid mode keys: wrapped software keys are also cleared.
  Future<bool?> deleteKeys() async {
    final response = await BiometricSignaturePlatform.instance.deleteKeys();
    return response;
  }

  /// Determines whether biometric authentication is available on the device.
  ///
  /// Returns:
  /// - `"fingerprint"`, `"face"`, `"iris"`, `"TouchID"`, `"FaceID"`, etc.
  /// - On Android, `"none, <reason>"` when unavailable.
  Future<String?> biometricAuthAvailable() async {
    return BiometricSignaturePlatform.instance.biometricAuthAvailable();
  }

  /// Checks whether a hardware-backed signing key currently exists.
  ///
  /// If [checkValidity] is `true`, the plugin attempts to initialize a
  /// signature operation. This may fail if the biometric enrollment has
  /// changed and the key has been invalidated.
  Future<bool?> biometricKeyExists({bool checkValidity = false}) async {
    return BiometricSignaturePlatform.instance.biometricKeyExists(
      checkValidity,
    );
  }
}
