import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(
  PigeonOptions(
    dartOut: 'lib/biometric_signature_platform_interface.pigeon.dart',
    dartOptions: DartOptions(),
    kotlinOut:
        'android/src/main/kotlin/com/visionflutter/biometric_signature/BiometricSignatureApi.kt',
    kotlinOptions: KotlinOptions(
      package: 'com.visionflutter.biometric_signature',
    ),
    swiftOut:
        'ios/biometric_signature/Sources/biometric_signature/BiometricSignatureApi.swift',
    swiftOptions: SwiftOptions(),
    cppSourceOut: 'windows/messages.g.cpp',
    cppHeaderOut: 'windows/messages.g.h',
    cppOptions: CppOptions(namespace: 'biometric_signature'),
  ),
)
/// The type of authentication that was used to complete an operation.
///
/// On Android, this is determined by the platform's `AuthenticationResult.getAuthenticationType()`.
/// On iOS/macOS, this is inferred: [biometric] if device credentials are not allowed,
/// [credential] if no biometric hardware is available, [unknown] otherwise.
/// On Windows, this is always [unknown] as Windows Hello handles auth internally.
enum AuthenticationType {
  /// The user authenticated using device credentials (PIN, pattern, or password).
  credential,

  /// The user authenticated using a biometric (fingerprint, face, iris).
  biometric,

  /// The authentication type could not be determined.
  unknown,
}

/// Types of biometric authentication supported by the device.
enum BiometricType {
  /// Face recognition (Face ID on iOS, face unlock on Android).
  face,

  /// Fingerprint recognition (Touch ID on iOS/macOS, fingerprint on Android).
  fingerprint,

  /// Iris scanner (Android only, rare on consumer devices).
  iris,

  /// Multiple biometric types are available on the device.
  multiple,

  /// No biometric hardware available or biometrics are disabled.
  unavailable,
}

/// Biometric authentication strength level.
///
/// This affects which biometric sensors can be used for authentication.
/// Note: On iOS/macOS, only strong biometrics are available (Face ID, Touch ID, Optic ID).
/// On Windows, Windows Hello always uses strong authentication.
enum BiometricStrength {
  /// Strong biometrics only (e.g., fingerprint, face recognition with depth sensing).
  /// This is the most secure option and is required for cryptographic operations.
  strong,

  /// Weak biometrics allowed (e.g., face recognition without depth sensing).
  /// This option provides more device compatibility but lower security.
  weak,
}

/// Standardized error codes for the plugin.
enum BiometricError {
  /// The operation was successful.
  success,

  /// The user canceled the operation.
  userCanceled,

  /// Biometric authentication is not available on this device.
  notAvailable,

  /// No biometrics are enrolled.
  notEnrolled,

  /// The user is temporarily locked out due to too many failed attempts.
  lockedOut,

  /// The user is permanently locked out until they log in with a strong method.
  lockedOutPermanent,

  /// The requested key was not found.
  keyNotFound,

  /// The key has been invalidated (e.g. by new biometric enrollment).
  keyInvalidated,

  /// An unknown error occurred.
  unknown,

  /// The input payload was invalid (e.g. not valid Base64).
  invalidInput,

  /// A security update is required before biometrics can be used.
  securityUpdateRequired,

  /// Biometric authentication is not supported on this device/OS version.
  notSupported,

  /// The system canceled the operation (e.g., app went to background).
  systemCanceled,

  /// Failed to show the biometric prompt (e.g., activity not available).
  promptError,

  /// A key with the specified alias already exists and failIfExists was set.
  keyAlreadyExists,

  /// The user selected a custom fallback option instead of authenticating.
  /// [Android 15+ only] Check `selectedFallbackIndex` and `selectedFallbackText`
  /// on the result object to determine which option was selected.
  fallbackSelected,

  /// The device does not have a screen lock (PIN, pattern, password, or
  /// passcode) configured.
  ///
  /// A screen lock is a prerequisite for biometric enrollment and for
  /// hardware-backed key storage on all platforms:
  /// - **iOS/macOS**: Maps from `kLAErrorPasscodeNotSet`. Can surface during
  ///   any operation that requires Secure Enclave access (key creation,
  ///   signing, decryption, and simple prompt).
  /// - **Android**: Maps from `ERROR_NO_DEVICE_CREDENTIAL` (cause code 14).
  ///   Only surfaces when `allowDeviceCredentials: true` is set; for
  ///   biometric-only flows Android reports [notAvailable] or [notEnrolled]
  ///   instead.
  /// - **Windows**: Not applicable — Windows Hello manages its own credential
  ///   requirements.
  ///
  /// Use [BiometricSignatureApi.isDeviceLockSet] as a proactive precondition
  /// check before attempting operations. This error is the reactive
  /// counterpart when the check is skipped or the user removes their screen
  /// lock between the check and the operation.
  ///
  /// **Migration from 11.0.x → 11.1.0**: On Android, `ERROR_NO_DEVICE_CREDENTIAL`
  /// (cause code 14) was previously mapped to [notAvailable]. Consumers that
  /// were pattern-matching on [notAvailable] to drive a "no screen lock" UX
  /// should migrate to [passcodeNotSet]. iOS/macOS mapping of
  /// `kLAErrorPasscodeNotSet` changed in the same release.
  passcodeNotSet,
}

/// A custom fallback option shown on the biometric prompt.
///
/// [Android 15+ only] When provided in a config's `fallbackOptions` list,
/// these appear as alternative buttons on the biometric prompt dialog.
/// If the user taps one, the result will have code [BiometricError.fallbackSelected]
/// with the selected option's index and text.
///
/// On iOS, macOS, and Windows this class is ignored.
class BiometricFallbackOption {
  /// The text label displayed on the fallback button.
  String? text;

  /// [Android] Optional icon type name for the fallback button.
  /// Valid values: `"password"`, `"qr_code"`, `"account"`, `"generic"`.
  /// Maps to `AuthenticationRequest.Biometric.Fallback.ICON_TYPE_*` constants.
  /// When null, defaults to `"generic"`.
  String? iconName;
}

class BiometricAvailability {
  bool? canAuthenticate;
  bool? hasEnrolledBiometrics;
  List<BiometricType?>? availableBiometrics;
  String? reason;
}

class KeyCreationResult {
  String? publicKey;
  Uint8List? publicKeyBytes;
  String? error;
  BiometricError? code;
  String? algorithm;
  int? keySize;
  String? decryptingPublicKey;
  String? decryptingAlgorithm;
  int? decryptingKeySize;
  bool? isHybridMode;

  /// The type of authentication used to complete this operation.
  ///
  /// Inferred on Apple platforms (iOS/macOS), authoritative on Android.
  /// See [AuthenticationType] for how inference is performed when the
  /// platform does not report the method directly.
  AuthenticationType? authenticationType;
}

class SignatureResult {
  String? signature;
  Uint8List? signatureBytes;
  String? publicKey;
  String? error;
  BiometricError? code;
  String? algorithm;
  int? keySize;

  /// [Android 15+] Index of the selected fallback option in the original list.
  /// Only populated when `code == BiometricError.fallbackSelected`.
  int? selectedFallbackIndex;

  /// [Android 15+] Text of the selected fallback option.
  /// Only populated when `code == BiometricError.fallbackSelected`.
  String? selectedFallbackText;

  /// The type of authentication used to complete this operation.
  ///
  /// Inferred on Apple platforms (iOS/macOS), authoritative on Android.
  /// See [AuthenticationType] for how inference is performed when the
  /// platform does not report the method directly.
  AuthenticationType? authenticationType;
}

class DecryptResult {
  String? decryptedData;
  String? error;
  BiometricError? code;

  /// [Android 15+] Index of the selected fallback option in the original list.
  /// Only populated when `code == BiometricError.fallbackSelected`.
  int? selectedFallbackIndex;

  /// [Android 15+] Text of the selected fallback option.
  /// Only populated when `code == BiometricError.fallbackSelected`.
  String? selectedFallbackText;

  /// The type of authentication used to complete this operation.
  ///
  /// Inferred on Apple platforms (iOS/macOS), authoritative on Android.
  /// See [AuthenticationType] for how inference is performed when the
  /// platform does not report the method directly.
  AuthenticationType? authenticationType;
}

/// Detailed information about existing biometric keys.
class KeyInfo {
  /// Whether any biometric key exists on the device.
  bool? exists;

  /// Whether the key is still valid (not invalidated by biometric changes).
  /// Only populated when `checkValidity: true` is passed.
  bool? isValid;

  /// The algorithm of the signing key (e.g., "RSA", "EC").
  String? algorithm;

  /// The key size in bits (e.g., 2048 for RSA, 256 for EC).
  int? keySize;

  /// Whether the key is in hybrid mode (separate signing and decryption keys).
  bool? isHybridMode;

  /// Signing key public key (formatted according to the requested format).
  String? publicKey;

  /// Decryption key public key for hybrid mode.
  String? decryptingPublicKey;

  /// Algorithm of the decryption key (hybrid mode only).
  String? decryptingAlgorithm;

  /// Key size of the decryption key in bits (hybrid mode only).
  int? decryptingKeySize;
}

/// The cryptographic algorithm to use for key generation.
enum SignatureType {
  /// RSA-2048 (Android: native, iOS/macOS: hybrid mode with Secure Enclave EC).
  rsa,

  /// ECDSA P-256 (hardware-backed on all platforms).
  ecdsa,
}

/// Configuration for key creation (all platforms).
///
/// Fields are documented with which platform(s) they apply to.
/// Windows ignores most fields as it only supports RSA with mandatory
/// Windows Hello authentication.
class CreateKeysConfig {
  // === Cross-platform options (availability varies by platform) ===

  /// [Android/iOS/macOS] The cryptographic algorithm to use.
  /// Windows only supports RSA and ignores this field.
  SignatureType? signatureType;

  /// [Android/iOS/macOS] Whether to require biometric authentication
  /// during key creation. Windows always authenticates via Windows Hello.
  bool? enforceBiometric;

  /// [Android/iOS/macOS] Whether to invalidate the key when new biometrics
  /// are enrolled. Not supported on Windows.
  ///
  /// **Security Note**: When `true`, keys become invalid if fingerprints/faces
  /// are added or removed, preventing unauthorized access if an attacker
  /// enrolls their own biometrics on a compromised device.
  bool? setInvalidatedByBiometricEnrollment;

  /// [Android/iOS/macOS] Whether to allow device credentials (PIN/pattern/passcode)
  /// as fallback for biometric authentication. Not supported on Windows.
  bool? useDeviceCredentials;

  /// [Android] Whether to enable decryption capability for the key.
  /// On iOS/macOS, decryption is always available with EC keys.
  bool? enableDecryption;

  // === Android prompt customization ===

  /// [Android] Subtitle text for the biometric prompt.
  String? promptSubtitle;

  /// [Android] Description text for the biometric prompt.
  String? promptDescription;

  /// [Android] Text for the cancel button in the biometric prompt.
  String? cancelButtonText;

  // === Key overwrite protection ===

  /// [All platforms] When `true`, key creation will fail with
  /// [BiometricError.keyAlreadyExists] if a key with the specified alias
  /// (or the default alias) already exists.
  ///
  /// When `false` (default), existing keys are silently replaced.
  bool? failIfExists;

  // === Custom fallback options ===

  /// [Android 15+] Custom fallback buttons shown on the biometric prompt.
  /// When provided, these replace the default cancel button.
  /// If the user taps a fallback option, the result will have
  /// `code == BiometricError.fallbackSelected` with the selected option's
  /// index and text. On other platforms, this field is ignored.
  List<BiometricFallbackOption?>? fallbackOptions;
}

/// Configuration for signature creation (all platforms).
///
/// Fields are documented with which platform(s) they apply to.
class CreateSignatureConfig {
  // === Android prompt customization ===

  /// [Android] Subtitle text for the biometric prompt.
  String? promptSubtitle;

  /// [Android] Description text for the biometric prompt.
  String? promptDescription;

  /// [Android] Text for the cancel button in the biometric prompt.
  String? cancelButtonText;

  /// [Android] Whether to allow device credentials (PIN/pattern) as fallback.
  bool? allowDeviceCredentials;

  // === iOS options ===

  /// [iOS] Whether to migrate from legacy keychain storage.
  bool? shouldMigrate;

  // === Custom fallback options ===

  /// [Android 15+] Custom fallback buttons shown on the biometric prompt.
  /// When provided, these replace the default cancel button.
  /// If the user taps a fallback option, the result will have
  /// `code == BiometricError.fallbackSelected` with the selected option's
  /// index and text. On other platforms, this field is ignored.
  List<BiometricFallbackOption?>? fallbackOptions;
}

/// Configuration for decryption (all platforms).
///
/// Fields are documented with which platform(s) they apply to.
/// Note: Decryption is not supported on Windows.
class DecryptConfig {
  // === Android prompt customization ===

  /// [Android] Subtitle text for the biometric prompt.
  String? promptSubtitle;

  /// [Android] Description text for the biometric prompt.
  String? promptDescription;

  /// [Android] Text for the cancel button in the biometric prompt.
  String? cancelButtonText;

  /// [Android] Whether to allow device credentials (PIN/pattern) as fallback.
  bool? allowDeviceCredentials;

  // === iOS options ===

  /// [iOS] Whether to migrate from legacy keychain storage.
  bool? shouldMigrate;

  // === Custom fallback options ===

  /// [Android 15+] Custom fallback buttons shown on the biometric prompt.
  /// When provided, these replace the default cancel button.
  /// If the user taps a fallback option, the result will have
  /// `code == BiometricError.fallbackSelected` with the selected option's
  /// index and text. On other platforms, this field is ignored.
  List<BiometricFallbackOption?>? fallbackOptions;
}

/// Output format for public keys.
enum KeyFormat {
  /// Base64-encoded DER (SubjectPublicKeyInfo).
  base64,

  /// PEM format with BEGIN/END PUBLIC KEY headers.
  pem,

  /// Hexadecimal-encoded DER.
  hex,

  /// Raw DER bytes (returned via `publicKeyBytes`).
  raw,
}

/// Output format for cryptographic signatures.
enum SignatureFormat {
  /// Base64-encoded signature bytes.
  base64,

  /// Hexadecimal-encoded signature bytes.
  hex,

  /// Raw signature bytes (returned via `signatureBytes`).
  raw,
}

/// Input format for encrypted payloads to decrypt.
enum PayloadFormat {
  /// Base64-encoded ciphertext.
  base64,

  /// Hexadecimal-encoded ciphertext.
  hex,

  /// Raw UTF-8 string (not recommended for binary data).
  raw,
}

@HostApi()
abstract class BiometricSignatureApi {
  /// Checks if biometric authentication is available.
  @async
  BiometricAvailability biometricAuthAvailable();

  /// Creates a new key pair.
  ///
  /// [keyAlias] is an optional alias for the key. When null, the default
  /// alias is used. Different aliases create independent key pairs.
  /// [config] contains platform-specific options. See [CreateKeysConfig].
  /// [keyFormat] specifies the output format for the public key.
  /// [promptMessage] is the message shown to the user during authentication.
  @async
  KeyCreationResult createKeys(
    String? keyAlias,
    CreateKeysConfig? config,
    KeyFormat keyFormat,
    String? promptMessage,
  );

  /// Creates a signature.
  ///
  /// [payload] is the data to sign.
  /// [keyAlias] specifies which key to sign with. Defaults to the default alias.
  /// [config] contains platform-specific options. See [CreateSignatureConfig].
  /// [signatureFormat] specifies the output format for the signature.
  /// [keyFormat] specifies the output format for the public key.
  /// [promptMessage] is the message shown to the user during authentication.
  @async
  SignatureResult createSignature(
    String payload,
    String? keyAlias,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  );

  /// Decrypts data.
  ///
  /// Note: Not supported on Windows.
  /// [payload] is the encrypted data.
  /// [keyAlias] specifies which key to decrypt with. Defaults to the default alias.
  /// [payloadFormat] specifies the format of the encrypted data.
  /// [config] contains platform-specific options. See [DecryptConfig].
  /// [promptMessage] is the message shown to the user during authentication.
  @async
  DecryptResult decrypt(
    String payload,
    String? keyAlias,
    PayloadFormat payloadFormat,
    DecryptConfig? config,
    String? promptMessage,
  );

  /// Deletes keys for a specific alias.
  ///
  /// [keyAlias] specifies which key to delete. When null, deletes the
  /// default alias only. Other aliases are not affected.
  @async
  bool deleteKeys(String? keyAlias);

  /// Deletes all biometric keys across all aliases.
  ///
  /// This is a destructive operation that removes every key managed by
  /// this plugin. Use [deleteKeys] for targeted deletion.
  @async
  bool deleteAllKeys();

  /// Gets detailed information about existing biometric keys.
  ///
  /// [keyAlias] specifies which key to query. Defaults to the default alias.
  /// Returns key metadata including algorithm, size, validity, and public keys.
  @async
  KeyInfo getKeyInfo(String? keyAlias, bool checkValidity, KeyFormat keyFormat);

  /// Performs simple biometric authentication without cryptographic operations.
  ///
  /// This is useful for:
  /// - Quick re-authentication flows
  /// - Confirming user presence before sensitive operations
  /// - Simple access control without key management
  ///
  /// [promptMessage] is the main message shown to the user (title on Android).
  /// [config] contains optional platform-specific configuration.
  ///
  /// Returns a [SimplePromptResult] indicating success or failure.
  @async
  SimplePromptResult simplePrompt(
    String promptMessage,
    SimplePromptConfig? config,
  );

  /// Checks whether the device has a screen lock (PIN, pattern, password, or
  /// passcode) configured.
  ///
  /// This is a precondition for biometric enrollment on most platforms, but
  /// the precise meaning of `true` varies per platform:
  ///
  /// - **Android**: Authoritative. Uses `KeyguardManager.isDeviceSecure()`
  ///   and reports exactly whether a lock credential is enrolled.
  /// - **iOS/macOS**: Evaluates `LAPolicy.deviceOwnerAuthentication` and
  ///   maps `kLAErrorPasscodeNotSet` to `false`. Any other failure to
  ///   evaluate the policy (e.g. on unusual or very old devices) is treated
  ///   as `true` to avoid false negatives. Therefore `true` means
  ///   "lock is set **or** indeterminate". If you need a stronger guarantee,
  ///   rely on the reactive [BiometricError.passcodeNotSet] surfaced during
  ///   the next operation.
  /// - **Windows**: Reports **Windows Hello availability**, not generic
  ///   screen-lock state. Uses
  ///   `KeyCredentialManager.IsSupportedAsync()`, which requires a Windows
  ///   Hello PIN to be provisioned. Password-only local accounts will get
  ///   `false` here even though a screen lock is set. Treat the Windows
  ///   return value as "can this device use Windows Hello for biometric
  ///   operations?" rather than a direct equivalent of the Android check.
  ///
  /// Returns `true` if the device has a screen lock configured (or the
  /// platform-specific equivalent described above).
  @async
  bool isDeviceLockSet();
}

/// Configuration for simple biometric prompt (authentication without crypto ops).
///
/// This allows customization of the biometric prompt across platforms.
class SimplePromptConfig {
  /// [Android] Subtitle text displayed below the title in the biometric prompt.
  String? subtitle;

  /// [Android] Description text displayed in the biometric prompt body.
  String? description;

  /// [Android] Text for the cancel/negative button.
  /// Default: "Cancel" on Android, system default on iOS/macOS.
  String? cancelButtonText;

  /// [Android/iOS/macOS] Whether to allow device credentials (PIN/pattern/passcode)
  /// as a fallback for biometric authentication.
  ///
  /// When true:
  /// - Android: Shows "Use PIN" option after biometric failure
  /// - iOS/macOS: Uses .deviceOwnerAuthentication policy
  /// - Windows: Not applicable (Windows Hello handles fallback internally)
  ///
  /// Default: false (biometric-only authentication)
  bool? allowDeviceCredentials;

  /// [Android] The required biometric strength level.
  ///
  /// - strong: Only Class 3 biometrics (e.g., fingerprint, in-screen fingerprint)
  /// - weak: Class 2 biometrics allowed (e.g., face unlock without depth)
  ///
  /// Note: iOS/macOS always use strong biometrics. Windows Hello also uses strong.
  /// If strong biometrics are not available but weak are, and strength is set to
  /// strong, authentication will fail with [BiometricError.notEnrolled].
  ///
  /// Default: strong
  BiometricStrength? biometricStrength;

  // === Custom fallback options ===

  /// [Android 15+] Custom fallback buttons shown on the biometric prompt.
  /// When provided, these replace the default cancel button.
  /// If the user taps a fallback option, the result will have
  /// `code == BiometricError.fallbackSelected` with the selected option's
  /// index and text. On other platforms, this field is ignored.
  List<BiometricFallbackOption?>? fallbackOptions;
}

/// Result from simple biometric prompt authentication.
class SimplePromptResult {
  /// Whether authentication was successful.
  bool? success;

  /// Error message if authentication failed.
  /// This is a human-readable description of what went wrong.
  String? error;

  /// Standardized error code if authentication failed.
  /// Use this for programmatic error handling.
  BiometricError? code;

  /// [Android 15+] Index of the selected fallback option in the original list.
  /// Only populated when `code == BiometricError.fallbackSelected`.
  int? selectedFallbackIndex;

  /// [Android 15+] Text of the selected fallback option.
  /// Only populated when `code == BiometricError.fallbackSelected`.
  String? selectedFallbackText;

  /// The type of authentication used to complete this operation.
  ///
  /// Inferred on Apple platforms (iOS/macOS), authoritative on Android.
  /// See [AuthenticationType] for how inference is performed when the
  /// platform does not report the method directly.
  AuthenticationType? authenticationType;
}
