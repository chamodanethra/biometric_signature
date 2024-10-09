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