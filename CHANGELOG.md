## 0.0.1

* initial release.

## 1.0.0

* improved documentation.

## 1.0.1

* downgrade min Dart Sdk.

## 1.0.2

* fixing createSignature's options param.

## 1.0.3

* upgrading dependencies.
* refactoring.

## 1.0.4

* upgrading flutter sdk to 3.7.11.
* improved documentation.

## 1.0.5

* improved documentation.

## 2.0.0

* Consistent Platform error handling.
* Upgrade dependencies.

## 2.1.0

* Returns "biometric" for Android devices with multiple BIOMETRIC_STRONG options when called
  biometricAuthAvailable().
* Let createSignature() accept a "payload" keyValue pair in options arg.
* updates dependencies.
* updates README.md and the Example.

## 2.1.1

* Removes a redundant code push in Android native code.
* Updates README.md and the Example.

## 2.1.2

### Fixed:

- Fixed the issue with the `createSignature()` method on Android, ensuring it doesn't do base64 encoding of the payload.
- Corrected the public key header in the `createKeys()` method on iOS to align with standard RSA key formats.

### Other Changes:

* Updated README.md and Licence content.

## 3.0.0

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

## 4.0.0

* Fixed a bug in createKeys() for iOS.
* Fixed a bug in createSignature() for android.
* Error codes were updated to maintain consistency.
* Updated README.md and Licence content.
* Hardcoded default payload was removed.
* Improved error handling.