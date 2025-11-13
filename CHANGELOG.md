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
