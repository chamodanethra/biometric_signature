## [11.1.0] - 2026-04-17

### Added
* **`isDeviceLockSet()` API:** New method on `BiometricSignature` to check whether a device-lock credential is configured. Android uses `KeyguardManager.isDeviceSecure()` (authoritative). iOS/macOS evaluate `LAPolicy.deviceOwnerAuthentication`; `true` means "set or indeterminate" — a stronger guarantee surfaces via the reactive `BiometricError.passcodeNotSet` during the next operation. Windows reports Windows Hello availability via `KeyCredentialManager.IsSupportedAsync()`, not a generic screen-lock state — see the dartdoc for details.
* **`AuthenticationType` reporting:** New `AuthenticationType` enum (`credential`, `biometric`, `unknown`) plus an `authenticationType` field on `KeyCreationResult`, `SignatureResult`, `DecryptResult`, and `SimplePromptResult`. Authoritative on Android (from `BiometricPrompt.AuthenticationResult`). Inferred on Apple platforms from the key's stored `useDeviceCredentials` flag and biometric hardware availability; returns `.unknown` when the stored flag is unavailable rather than falsely reporting `.biometric`. Always `.unknown` on Windows.
* **`BiometricError.passcodeNotSet`:** Dedicated error code for "device has no screen lock / passcode configured", distinct from `notAvailable`.

### Fixed
* **iOS/macOS `authenticationType` inference:** The `useDeviceCredentials` flag is now persisted in the keychain at key-creation time and read during sign/decrypt, replacing the previous signing-time heuristic that could not produce an accurate result.
* **iOS/macOS keychain accessibility:** The `DeviceCredentialsSetting` keychain item is now created with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, matching the lifetime of the Secure Enclave key it accompanies and keeping the flag device-local.

### Changed
* **Breaking (behavioural) — Android error mapping:** `ERROR_NO_DEVICE_CREDENTIAL` (cause code 14) now maps to `BiometricError.passcodeNotSet` instead of `BiometricError.notAvailable`. Consumers that were pattern-matching on `BiometricError.notAvailable` to drive a "no screen lock" UX must update their switch statements to handle `BiometricError.passcodeNotSet`. This is a minor-version bump because the Dart API surface is unchanged; only the runtime error value differs.
* **Breaking (behavioural) — iOS/macOS error mapping:** `kLAErrorPasscodeNotSet` now maps to `BiometricError.passcodeNotSet` instead of `BiometricError.notAvailable`. Same migration guidance as above.

## [11.0.2] - 2026-04-02

* Documentation updates.
* Bug fixes.

## [11.0.1] - 2026-03-28

### Fixed
* Fixed macOS SPM issue.

## [11.0.0] - 2026-03-28

### Added
* **Named Key Aliases:** All key operations (`createKeys`, `createSignature`, `decrypt`, `deleteKeys`, `getKeyInfo`, `biometricKeyExists`) now accept an optional `keyAlias` parameter, allowing apps to manage multiple independent key pairs (e.g., one for auth, one for payment signing).
* **Key Overwrite Protection:** `CreateKeysConfig.failIfExists` prevents accidental key replacement. When `true`, `createKeys()` fails with `BiometricError.keyAlreadyExists` if a key with the specified alias already exists.
* **Delete All Keys:** New `deleteAllKeys()` method removes all plugin-managed keys across all aliases.
* **Custom Fallback Options (Android 15+):** All config classes (`CreateKeysConfig`, `CreateSignatureConfig`, `DecryptConfig`, `SimplePromptConfig`) now support `fallbackOptions` — a list of `BiometricFallbackOption` items that appear as custom buttons on the biometric prompt. When the user taps a fallback option, the result contains `BiometricError.fallbackSelected` with `selectedFallbackIndex` and `selectedFallbackText`.
* **OAEP Padding for RSA:** RSA encryption now uses OAEP padding with PKCS#1 v1.5 fallback for improved security.
* **Atomic File Writing:** Sensitive key material writes use atomic file operations to prevent data corruption.

### Fixed
* **`KEY_INVALIDATED` Error Mapping:** `BiometricError.keyInvalidated` is now correctly returned when keys have been invalidated by biometric enrollment changes on Android.
* **Android Coroutine Dispatching:** Key management operations now use proper coroutine dispatchers (IO for file/crypto operations).
* **CancellationException Handling:** Structured concurrency is preserved — `CancellationException` is always rethrown, preventing callbacks to a detached Flutter engine.
* **Hybrid Key Cleanup:** If the second biometric authentication fails during hybrid key creation, partially-created keys are now cleaned up.

### Changed
* **Modularized Android Architecture:** Extracted Android plugin into focused helper classes (`BiometricPromptHelper`, `CryptoOperations`, `ErrorMapper`, `FileIOHelper`, `FormatUtils`, `KeyManager`).
* **Unified macOS/iOS Plugin:** Consolidated Swift plugin code using conditional compilation (`#if os(macOS)`) to support both platforms from a single source file.
* **Refined ProGuard Rules:** Updated Android ProGuard/R8 rules for better compatibility.

## [10.2.0] - 2026-03-03

* Enhance biometric key security on iOS/macOS.
* Enforce CryptoObject usage for Android signatures.
* Add Android ProGuard rules.

## [10.1.0] - 2026-02-19

* Added Swift Package Manager (SPM) support for iOS and macOS plugin integration.
* Migrated iOS/macOS native source layout to `Package.swift` + `Sources/<plugin_name>/`.
* Updated Pigeon generation output paths for Darwin host code to match the SPM layout.
* Updated CocoaPods podspecs to remain compatible alongside SPM.
* Updated package and platform version references/documentation.
* **Fix:** Enhanced biometric type detection for android.

## [10.0.0] - 2026-02-06

* **Breaking:** Added new `BiometricError` enum values; consumers using exhaustive switches must handle the new cases(security update required, not supported, system canceled, prompt error).
* **Feature:** Added `simplePrompt()` for lightweight biometric authentication without cryptographic operations.
* **Fix:** Improved Android error handling and prompt robustness.
* **Fix:** Aligned iOS/macOS error mapping with Android.
* **Docs:** Updated README and usage examples.

## [9.0.3] - 2026-01-25

* Reduced published package size by ~45%.

## [9.0.2] - 2026-01-24

* **Package Optimization:** Reduced published package size significantly:
  - Converted `assets/logo.png` (1.0 MB) to `assets/logo.jpeg` (120 KB), reducing image size by ~90%
  - Added `.pubignore` to exclude example applications (`banking_app`, `document_signer`, `passwordless_login`) from published package
  - Total package size reduced from ~2 MB to ~535 KB
* **Maintenance:** Updated version references across all platform files and documentation.
* Minor bug fix.
* Enhanced the passwordless login example.
* Added "Migration Guide" section to the README.md.

## [9.0.1] - 2025-12-21

* **Feature:** Added "Biometric Decryption" section to `README.md` with a detailed lifecycle diagram (`usecase-2.png`) and process description.
* **Improved:** Enhanced Windows platform documentation to clarify `KeyCredentialManager` usage, TPM backing, RSA-2048 constraints, and lack of decryption support.
* **Metadata:** Updated `pubspec.yaml` description to explicitly include supported platforms and Windows Hello.
* **Maintenance:** Updated Android native dependency.

## [9.0.0] - 2025-12-18

* **Breaking**: Method signature changes:
  - `createKeys()` now takes `config`, `keyFormat`, `promptMessage` parameters
  - `createSignature()` now takes `payload`, `config`, `signatureFormat`, `keyFormat`, `promptMessage` parameters
  - `decrypt()` now takes `payload`, `payloadFormat`, `config`, `promptMessage` parameters

* Moved cross-platform parameters into unified config objects:
  - `signatureType`, `enforceBiometric`, `setInvalidatedByBiometricEnrollment`, `useDeviceCredentials` now in `CreateKeysConfig`
  - Each field is documented with which platform(s) it applies to

### Architecture - Type-safe Communication with Pigeon
* **Breaking**: Migrated entire platform communication layer to [Pigeon](https://pub.dev/packages/pigeon).
* **Breaking**: Replaced raw string/map returns with structured strongly-typed objects:
  - `KeyCreationResult`: Contains `publicKey`, `error`, and `code`.
  - `SignatureResult`: Contains `signature`, `publicKey`, `error`, and `code`.
  - `DecryptResult`: Contains `decryptedData`, `error`, and `code`.
  - `BiometricAvailability`: detailed availability status including enrolled biometric types and error reasons.
* **Breaking**: Standardized `BiometricError` enum across all platforms.

### API Improvements
* **Breaking**: `biometricAuthAvailable()` now returns a `BiometricAvailability` object instead of a raw string.
* Removed legacy `signature_options.dart`, `decryption_options.dart` and old config classes.
* Enhanced error handling with specific error codes (e.g., `userCanceled`, `notEnrolled`, `lockedOut`) instead of generic strings.
* **New `getKeyInfo()` method**: Retrieve detailed information about existing biometric keys without creating a signature.
    - Returns `KeyInfo` object with: `exists`, `isValid`, `algorithm`, `keySize`, `isHybridMode`, `publicKey`, `decryptingPublicKey`.
    - Accepts `checkValidity` parameter to verify key hasn't been invalidated by biometric changes.
    - Accepts `keyFormat` parameter to specify output format (base64, pem, hex).
* **New `KeyInfo` class**: Exported via Pigeon for type-safe key metadata.
* `biometricKeyExists()` is now a convenience wrapper around `getKeyInfo()`.

### Improved
* Cleaner, simpler API with fewer method parameters
* Better documentation of platform-specific options
* Updated all example projects to use new API

## [8.5.0] - 2025-12-09

### Added - macOS Platform Support

#### Platform Integration
* **Full macOS support** for biometric authentication using Touch ID.
* Native macOS implementation via `BiometricSignaturePlugin.swift`.
* Support for macOS 10.15 (Catalina) and later.
* CocoaPods integration for seamless dependency management.

#### API and Configuration
* New `MacosConfig` class for platform-specific configuration:
  - `useDeviceCredentials`: Enable device credentials (passcode) fallback
  - `signatureType`: Support for both `MacosSignatureType.RSA` and `MacosSignatureType.ECDSA`
  - `biometryCurrentSet`: Bind keys to current Touch ID enrollment state
* **New Parameter**: Added optional `promptMessage` parameter to `createKeys()` method across all platforms
  - Allows customization of the authentication prompt when `enforceBiometric` is `true`
  - Defaults to `"Authenticate to create keys"` for backward compatibility
  - Provides context-specific instructions to users during key generation

#### Security Features
* **App-specific keychain isolation**: Keychain identifiers now incorporate bundle identifier to prevent cross-app conflicts on macOS
  - Each app's keys are completely isolated: `{bundleId}.eckey`, `{bundleId}.biometric_key`, etc.
  - Solves the issue where multiple apps using the plugin would share the same keychain items
  - iOS implementation remains unchanged as it already has proper sandboxing
* Secure Enclave integration for EC key storage and operations
* Hardware-backed cryptographic operations using macOS Security framework
* Domain state tracking for biometric enrollment changes

#### Cryptographic Features
* **RSA Mode**: 
  - RSA-2048 hardware-backed signing
  - Hybrid mode with software RSA decryption key wrapped via ECIES
* **EC Mode**: 
  - P-256 (secp256r1) hardware-backed signing in Secure Enclave
  - Native ECIES decryption using `SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM`
  - Support for EC-only mode and hybrid EC mode

#### Implementation Details
* Biometry change detection via `LAContext.evaluatedPolicyDomainState`
* Automatic key invalidation when Touch ID enrollment changes (when `biometryCurrentSet` is `true`)
* Support for all key formats: BASE64, PEM, RAW, HEX
* Consistent error handling and Flutter method channel integration

### Changed
* Updated platform interface to distinguish macOS from iOS
* Enhanced `BiometricSignaturePlatform` to properly handle macOS-specific parameters
* Updated documentation with macOS integration steps and examples
* Added macOS to platform support table (macOS 10.15+)

## [8.4.0] - 2025-11-28
### Added
* **ECIES decryption** on Android and iOS.
* X9.63-SHA256 KDF and AES-128-GCM support for elliptic-curve decryption.
* RSA decryption support via `decrypt()` on Android and iOS.
* `enableDecryption` option in `AndroidConfig` to generate RSA keys with decryption capability.
* Cross-platform ECIES support for P-256 (secp256r1) keys.

### Android
* Manual ECIES implementation using ECDH, X9.63 KDF, and AES-GCM.
* Software EC private key for decryption is encrypted using a biometric-protected AES-256 master key (Keystore/StrongBox).
* Wrapped EC private key blob is stored in app-private files with MODE_PRIVATE permissions.
* All sensitive key material is zeroized after use.

### iOS
* Native ECIES support through SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM.
* Hybrid RSA mode: software RSA key for decryption encrypted via ECIES with Secure Enclave EC public key.

### Architecture

* Updated hybrid EC design:
    * Android: hardware EC signing key + AES-wrapped software EC decryption key
    * iOS: hardware EC signing key + ECIES-wrapped software RSA key

### Misc

* Expanded documentation and updated examples.
* Improved test coverage across decryption and hybrid modes.

## [8.3.1] - 2025-11-20

* Optimize iOS createKeys implementation.
* ReadMe.md was updated.

## [8.3.0] - 2025-11-20

* Added `enforceBiometric` parameter to `createKeys()` method to require biometric authentication before generating the key-pair.
* Added an optional subtitle parameter to Android biometric prompts via `AndroidSignatureOptions`.
* ReadMe.md and example updates.

## [8.2.0] - 2025-11-13

* Upgraded Flutter from 3.32.8 to 3.35.7
* Upgraded Dart SDK from ^3.8.1 to ^3.9.2
* iOS minimum deployment target upgraded from 12.0 to 13.0
* Android minimum SDK upgraded from 23 to 24
* Upgraded Android Gradle Plugin from 8.7.3 to 8.9.1
* Upgraded Android compileSdk from 35 to 36
* Refactored Android native code to use internal objects for error constants and key aliases
* Code quality improvements: formatting and style consistency updates across example projects

## [8.1.1] - 2025-11-09

* A small [bug](https://github.com/chamodanethra/biometric_signature/pull/46#discussion_r2507781143) was fixed.

# [8.1.0] - 2025-11-09

* Added an optional parameter to configure whether the key should be invalidated on new biometric enrollment when creating the key.

## [8.0.0] - 2025-10-15

* **Breaking**: `createKeys` now returns a `KeyCreationResult` instead of a plain base64 string, enabling configurable output formats.
* **Breaking**: `createSignature` returns a `SignatureResult` that includes both the formatted signature and public key metadata.
* Added `KeyFormat` support across Dart, Android, and iOS with BASE64, PEM, RAW (DER/bytes), and HEX representations.
* Android: refactored native layer to emit structured maps, generate PEM blocks directly, and expose raw DER bytes when requested.
* iOS: aligned public key formatting with SubjectPublicKeyInfo, added PEM/RAW/HEX conversions, and unified signature responses.
* Updated documentation, examples, and helper classes to illustrate working with `FormattedValue` utilities.
* Removed `createSignatureFromLegacyOptions` helper.

## [7.0.4] - 2025-10-03
* ReadMe.md updates.
* Reverting back to previous iOS IPHONEOS_DEPLOYMENT_TARGET(12.0).
* Added 3 practical-world examples.

## [7.0.3] - 2025-09-28
* Updating documentations.
* Minor bug fixes.

## [7.0.2] - 2025-09-26
* Fix formatting errors.

## [7.0.1] - 2025-09-26
* Updating documentations.

## [7.0.0] - 2025-09-26

* **Breaking**: Replace the map-based `createSignature` API with typed `SignatureOptions`, plus platform-specific option classes.
* Added `createSignatureFromLegacyOptions` helper to ease migration from the legacy API.
* Fixed Android `allowDeviceCredentials` parsing so boolean values are honoured.
* Updated the iOS plugin to accept native booleans for `shouldMigrate`.
* Improved Android native Kotlin coroutines implementation.
* Updated native dependencies.

## [6.4.2] - 2025-09-21

* The migrate path for iOS from 5.x is preserved.
* ReadMe.md updates.

## [6.4.1] - 2025-09-18

* Suggesting a fix for [issue](https://github.com/chamodanethra/biometric_signature/issues/39).

## [6.4.0] - 2025-09-17

* Suggesting a fix for [issue](https://github.com/chamodanethra/biometric_signature/issues/36) using Kotlin coroutines.

## [6.3.1] - 2025-09-02

* fix dart formatting errors.

## [6.3.0] - 2025-09-02

* Upgrading Flutter from 3.27.2 to 3.32.8.
* Updating the README.md file descriptions.
* Adding ECDSA Key support for cryptographic operations.
* Suggesting a fix for [issue](https://github.com/chamodanethra/biometric_signature/issues/30).

## [6.2.1] - 2025-09-17

* Suggesting a fix for [issue](https://github.com/chamodanethra/biometric_signature/issues/39).

## [6.2.0] - 2025-01-15

* Upgrading Flutter from 3.27.0 to 3.27.2.
* Updating the README.md file descriptions.
* Device Credentials' fallback support for compatible devices can be configured.

## [6.1.0] - 2025-01-06

* Feature - Allow Device Credentials as a fallback for biometric authentication.

## [6.0.0] - 2024-12-29

* Upgrading Flutter from 3.19.6 to 3.27.0

## [5.1.4] - 2025-08-28

* A [bug](https://github.com/chamodanethra/biometric_signature/issues/31) fix for key user not authenticated android crash.

## [5.1.3] - 2024-12-03

* A [bug](https://github.com/chamodanethra/biometric_signature/issues/24) fix for android KeyStoreException crash.

## [5.1.2] - 2024-11-19

* A [bug](https://github.com/chamodanethra/biometric_signature/issues/20) fix in iOS createKeys() flow.

## [5.1.1] - 2024-09-20

* ReadMe.md updates.

## [5.1.0] - 2024-09-19

* **Feature** Secure Enclave migration from Key Chain.

## [5.0.0] - 2024-09-15

* Secure Enclave integration in iOS.

## [4.2.0] - 2024-09-14

* Fix [iOs issue: biometricKeyExists always false ](https://github.com/chamodanethra/biometric_signature/issues/12).

## [4.1.1] - 2024-08-26

* Fix linting issues.

## [4.1.0] - 2024-08-25

* **Feature** Use StrongBox in compatible android devices.
* Refactor key creation to use AndroidConfig object.

## [4.0.3] - 2024-07-27

* fix Local Authentication bypass in iOS when calling createSignature().

## [4.0.2] - 2024-07-22

* fix Biometric portal not coming up in iOS simulators when calling createSignature().
* General improvements.

## [4.0.1] - 2024-06-30

* A crash on Android devices below API level 28 was fixed.
* General improvements.

## [4.0.0] - 2024-06-12

* Fixed a bug in createKeys() for iOS.
* Fixed a bug in createSignature() for android.
* Error codes were updated to maintain consistency.
* Updated README.md and Licence content.
* Hardcoded default payload was removed.
* Improved error handling.

## [3.0.0] - 2024-06-02

### New Features:

* The plugin offers more flexibility for advanced use cases, such as handling different biometric modalities and customizing the signature generation process.

### Bug Fixes:

* Improved the handling of biometric prompt cancellations.
* Enhanced the accuracy of biometric authentication on some devices.

### Other Changes:

* Updated the plugin's documentation to reflect the new features and improvements.
* Migrated the plugin to use the latest Flutter development tools.
* Improved the overall performance and stability of the plugin.
* This version is now compatible with AGP >=7.3 including 8.x support.

### Breaking Changes:

* The minimum supported Flutter version has been increased to 3.3.0.

## [2.1.2] - 2024-06-14

### Fixed:

- **Android**: Fixed the issue with the `createSignature()` method, ensuring it doesn't encode the payload to base64.
- **iOS**: Corrected the public key header in `createKeys()` method to align with standard RSA key formats.

### Other Changes:

* Updated README.md and Licence content.

## [2.1.1] - 2024-05-25

* Removes a redundant code push in Android native code.
* Updates README.md and the Example.

## [2.1.0] - 2024-05-24

* Returns "biometric" for Android devices with multiple BIOMETRIC_STRONG options when called
  biometricAuthAvailable().
* Let createSignature() accept a "payload" keyValue pair in options arg.
* updates dependencies.
* updates README.md and the Example.

## [2.0.0] - 2023-04-29

* Consistent Platform error handling.
* Upgrade dependencies.

## [1.0.5] - 2023-04-17

* improved documentation.

## [1.0.4] - 2023-04-16

* upgrading flutter sdk to 3.7.11.
* improved documentation.

## [1.0.3] - 2023-03-15

* upgrading dependencies.
* refactoring.

## [1.0.2] - 2023-02-07

* fixing createSignature's options param.

## [1.0.1] - 2023-01-29

* downgrade min Dart Sdk.

## [1.0.0] - 2023-01-29

* improved documentation.

## [0.0.1] - 2023-01-29

* initial release.
