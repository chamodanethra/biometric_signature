## [6.1.0] - 2025-01-06

* Feature - Allow Device Credentials as a fallback for biometric authentication.

## [6.0.0] - 2024-12-29

* Upgrading Flutter from 3.19.6 to 3.27.0

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
