import 'biometric_signature_platform_interface.dart';

export 'biometric_signature_platform_interface.dart'
    show
        AuthenticationType,
        BiometricFallbackOption,
        CreateKeysConfig,
        CreateSignatureConfig,
        DecryptConfig,
        SignatureType,
        KeyFormat,
        SignatureFormat,
        PayloadFormat,
        BiometricError,
        BiometricType,
        BiometricStrength,
        BiometricAvailability,
        KeyCreationResult,
        SignatureResult,
        DecryptResult,
        KeyInfo,
        SimplePromptConfig,
        SimplePromptResult;

/// High-level API for interacting with the Biometric Signature plugin.
class BiometricSignature {
  /// Creates a new biometric-protected key pair.
  ///
  /// [keyAlias] is an optional name for this key pair. Different aliases
  /// create independent key pairs, allowing apps to manage multiple keys
  /// (e.g., one for auth, one for payment signing). When null, the default
  /// alias is used.
  /// [config] contains platform-specific options. See [CreateKeysConfig] for
  /// available options and which platforms they apply to.
  /// [keyFormat] specifies the output format for the public key.
  /// [promptMessage] is the message shown during biometric authentication.
  ///
  /// Returns a [KeyCreationResult] containing the public key or error details.
  Future<KeyCreationResult> createKeys({
    String? keyAlias,
    CreateKeysConfig? config,
    KeyFormat keyFormat = KeyFormat.base64,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.createKeys(
      keyAlias,
      config,
      keyFormat,
      promptMessage,
    );
  }

  /// Creates a digital signature using biometric authentication.
  ///
  /// [payload] is the data to sign.
  /// [keyAlias] specifies which key to sign with. Defaults to the default alias.
  /// [config] contains platform-specific options. See [CreateSignatureConfig].
  /// [signatureFormat] specifies the output format for the signature.
  /// [keyFormat] specifies the output format for the public key.
  /// [promptMessage] is the message shown during biometric authentication.
  ///
  /// Returns a [SignatureResult] containing the signature or error details.
  Future<SignatureResult> createSignature({
    required String payload,
    String? keyAlias,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat = SignatureFormat.base64,
    KeyFormat keyFormat = KeyFormat.base64,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.createSignature(
      payload,
      keyAlias,
      config,
      signatureFormat,
      keyFormat,
      promptMessage,
    );
  }

  /// Decrypts data using biometric authentication.
  ///
  /// Note: Not supported on Windows.
  ///
  /// [payload] is the encrypted data.
  /// [keyAlias] specifies which key to decrypt with. Defaults to the default alias.
  /// [payloadFormat] specifies the format of the encrypted data.
  /// [config] contains platform-specific options. See [DecryptConfig].
  /// [promptMessage] is the message shown during biometric authentication.
  ///
  /// Returns a [DecryptResult] containing the decrypted data or error details.
  Future<DecryptResult> decrypt({
    required String payload,
    required PayloadFormat payloadFormat,
    String? keyAlias,
    DecryptConfig? config,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.decrypt(
      payload,
      keyAlias,
      payloadFormat,
      config,
      promptMessage,
    );
  }

  /// Deletes biometric key material for a specific alias.
  ///
  /// [keyAlias] specifies which key to delete. When null, deletes the
  /// default alias only. Other aliases are not affected.
  ///
  /// Returns `true` if keys were deleted or no keys existed for the alias.
  Future<bool> deleteKeys({String? keyAlias}) async {
    return BiometricSignaturePlatform.instance.deleteKeys(keyAlias);
  }

  /// Deletes all biometric key material across all aliases.
  ///
  /// This is a destructive operation. Use [deleteKeys] with a specific
  /// alias for targeted deletion.
  ///
  /// Returns `true` if all keys were deleted.
  Future<bool> deleteAllKeys() async {
    return BiometricSignaturePlatform.instance.deleteAllKeys();
  }

  /// Determines whether biometric authentication is available on the device.
  ///
  /// Returns a [BiometricAvailability] with details about available biometrics.
  Future<BiometricAvailability> biometricAuthAvailable() async {
    return BiometricSignaturePlatform.instance.biometricAuthAvailable();
  }

  /// Gets detailed information about existing biometric keys.
  ///
  /// [keyAlias] specifies which key to query. Defaults to the default alias.
  /// [checkValidity] whether to verify key hasn't been invalidated.
  /// [keyFormat] output format for the public key.
  ///
  /// Returns a [KeyInfo] with key metadata.
  Future<KeyInfo> getKeyInfo({
    String? keyAlias,
    bool checkValidity = false,
    KeyFormat keyFormat = KeyFormat.base64,
  }) async {
    return BiometricSignaturePlatform.instance.getKeyInfo(
      keyAlias,
      checkValidity,
      keyFormat,
    );
  }

  /// Checks whether a hardware-backed signing key currently exists.
  ///
  /// [keyAlias] specifies which key to check. Defaults to the default alias.
  /// This is a convenience wrapper around [getKeyInfo].
  Future<bool> biometricKeyExists({
    String? keyAlias,
    bool checkValidity = false,
  }) async {
    final info = await getKeyInfo(
      keyAlias: keyAlias,
      checkValidity: checkValidity,
    );
    return (info.exists ?? false) && (info.isValid ?? true);
  }

  /// Performs simple biometric authentication without cryptographic operations.
  ///
  /// This is useful for:
  /// - Quick re-authentication flows (e.g., unlock app after timeout)
  /// - Confirming user presence before sensitive operations
  /// - Simple access control without key management overhead
  ///
  /// Unlike [createSignature] or [createKeys], this method does not require
  /// any key material and simply verifies the user's biometric identity.
  ///
  /// [promptMessage] is the main message shown to the user. On Android, this
  /// is used as the dialog title. On iOS/macOS, this is the localized reason.
  ///
  /// [config] contains optional platform-specific configuration. See [SimplePromptConfig].
  ///
  /// Returns a [SimplePromptResult] indicating success or failure with error details.
  Future<SimplePromptResult> simplePrompt({
    required String promptMessage,
    SimplePromptConfig? config,
  }) async {
    return BiometricSignaturePlatform.instance.simplePrompt(
      promptMessage,
      config,
    );
  }

  /// Checks whether the device has a screen lock (PIN, pattern, password, or
  /// passcode) configured.
  ///
  /// This is a precondition for biometric enrollment on most platforms. If
  /// this returns `false`, the user typically needs to set up a device lock
  /// before biometrics can be used.
  ///
  /// Platform behavior — note the semantics differ:
  /// - **Android**: Authoritative. `KeyguardManager.isDeviceSecure()`.
  /// - **iOS/macOS**: Evaluates `LAPolicy.deviceOwnerAuthentication`.
  ///   Returns `false` only for the specific `kLAErrorPasscodeNotSet` error;
  ///   other failures to evaluate the policy fall through to `true` to avoid
  ///   false negatives, so `true` means "set **or** indeterminate". For a
  ///   stronger guarantee, rely on [BiometricError.passcodeNotSet] surfaced
  ///   by the next real operation.
  /// - **Windows**: Reports **Windows Hello availability** (via
  ///   `KeyCredentialManager.IsSupportedAsync()`), not generic screen-lock
  ///   state. A Windows Hello PIN is required for `true`; password-only
  ///   accounts get `false` even with a screen lock configured.
  Future<bool> isDeviceLockSet() async {
    return BiometricSignaturePlatform.instance.isDeviceLockSet();
  }
}
