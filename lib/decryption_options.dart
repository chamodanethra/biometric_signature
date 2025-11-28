/// Configuration for controlling how a decryption request is executed.
///
/// Decryption is performed using the key material currently stored on the
/// device. The plugin automatically selects the appropriate algorithm based
/// on the active key mode (RSA, EC signing-only, or Hybrid EC).
///
/// ## Supported Algorithms
///
/// **RSA Decryption**
/// - Uses RSA/ECB/PKCS1Padding on both Android and iOS.
///
/// **EC Decryption (ECIES)**
/// - Uses ECIES with ANSI X9.63 KDF (SHA-256) and AES-128-GCM.
/// - Android:
///   - ECIES is implemented manually (ECDH → X9.63 KDF → AES-GCM).
///   - The software EC private key is stored in app-private files (encrypted),
///     and unwrapped at runtime using a biometric-protected AES-256 master key
///     stored inside Keystore/StrongBox.
/// - iOS:
///   - ECIES is performed natively using
///     `SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM`.
///
/// ## Payload Format
///
/// The encrypted payload must be Base64-encoded:
///
/// - **RSA:**
///   A standard PKCS#1 RSA block.
///
/// - **EC (ECIES):**
///   `ephemeralPubKey(65 bytes) || ciphertext || gcmTag(16 bytes)`
///
/// The plugin validates and parses this structure automatically.
class DecryptionOptions {
  /// Creates a new [DecryptionOptions] instance.
  const DecryptionOptions({
    required this.payload,
    this.promptMessage,
    this.androidOptions,
    this.iosOptions,
  });

  /// Base64-encoded encrypted payload.
  ///
  /// - **RSA:** PKCS#1-encoded block.
  /// - **EC:** Concatenated ECIES blob consisting of:
  ///   - Uncompressed ephemeral public key (65 bytes: `0x04 || X || Y`)
  ///   - AES-GCM ciphertext
  ///   - 16-byte GCM authentication tag
  final String payload;

  /// Optional custom message shown in the biometric authentication prompt.
  final String? promptMessage;

  /// Android-specific biometric and prompt configuration.
  final AndroidDecryptionOptions? androidOptions;

  /// iOS-specific configuration, including optional migration of legacy keys.
  final IosDecryptionOptions? iosOptions;

  /// Converts this object to a map suitable for method-channel transport.
  Map<String, dynamic> toMethodChannelMap() {
    final map = <String, dynamic>{
      'payload': payload,
      if (promptMessage != null) 'promptMessage': promptMessage,
    };

    if (androidOptions != null) {
      map.addAll(androidOptions!.toMethodChannelMap());
    }

    if (iosOptions != null) {
      map.addAll(iosOptions!.toMethodChannelMap());
    }

    return map;
  }
}

/// Android-specific decryption parameters.
class AndroidDecryptionOptions {
  /// Creates a new [AndroidDecryptionOptions] instance.
  const AndroidDecryptionOptions({
    this.cancelButtonText,
    this.allowDeviceCredentials,
    this.subtitle,
  });

  /// Text displayed on the cancel button in the biometric prompt.
  final String? cancelButtonText;

  /// Whether device credentials (PIN / Pattern / Password) may satisfy the
  /// biometric prompt on Android 11+.
  final bool? allowDeviceCredentials;

  /// Optional subtitle displayed beneath the prompt title.
  final String? subtitle;

  /// Whether any Android-specific parameters were provided.
  bool get hasValues =>
      cancelButtonText != null ||
      allowDeviceCredentials != null ||
      subtitle != null;

  /// Converts Android-specific options to a method-channel-compatible map.
  Map<String, dynamic> toMethodChannelMap() {
    return {
      if (cancelButtonText != null) 'cancelButtonText': cancelButtonText,
      if (allowDeviceCredentials != null)
        'allowDeviceCredentials': allowDeviceCredentials,
      if (subtitle != null) 'subtitle': subtitle,
    };
  }
}

/// iOS-specific decryption parameters.
class IosDecryptionOptions {
  /// Creates a new [IosDecryptionOptions] instance.
  const IosDecryptionOptions({this.shouldMigrate});

  /// Whether legacy (pre-5.x) Keychain keys should be migrated into the
  /// Secure Enclave during the decryption request.
  ///
  /// Migration is only required when supporting older installations; new
  /// deployments can leave this disabled for optimal performance.
  final bool? shouldMigrate;

  /// Whether any iOS-specific parameters were provided.
  bool get hasValues => shouldMigrate != null;

  /// Converts iOS-specific options to a method-channel-compatible map.
  Map<String, dynamic> toMethodChannelMap() {
    return {if (shouldMigrate != null) 'shouldMigrate': shouldMigrate};
  }
}
