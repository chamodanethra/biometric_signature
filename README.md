# biometric_signature

Biometric Signature is a Flutter plugin that simplifies the process of integrating biometric
authentication (fingerprint, facial, and iris recognition) into your Dart and Flutter applications.
It is designed to provide a consistent user experience across both Android and iOS platforms, with
customizable UI components and high-level abstractions for biometric signature management.

## Features

- StrongBox support in compatible Android devices and Secure Enclave integration in iOS
- Fingerprint, facial, and iris recognition (based on device capabilities)
- Device Credentials' fallback support for compatible devices can be configured
- Simple integration with Dart and Flutter applications
- Customizable UI components for signature prompts
- High-level abstractions for managing biometric signatures

## Getting Started

To get started with Biometric Signature, follow these steps:

1. Add the package to your project by including it in your `pubspec.yaml` file:

```yaml
dependencies:
  biometric_signature: ^7.0.4
```

|             | Android | iOS   |
|-------------|---------|-------|
| **Support** | SDK 23+ | 13.0+ |

### iOS Integration

This plugin works with Touch ID **or** Face ID. To use Face ID in available devices,
you need to add:

```xml

<dict>
    <key>NSFaceIDUsageDescription</key>
    <string>This app is using FaceID for authentication</string>
</dict>
```

to your Info.plist file.

### Android Integration

#### Activity Changes

This plugin requires the use of a FragmentActivity as opposed to Activity. This can be easily done
by switching to use FlutterFragmentActivity as opposed to FlutterActivity in your manifest or your
own Activity class if you are extending the base class.

#### Permissions

Update your project's `AndroidManifest.xml` file to include the
`USE_BIOMETRIC` permission.

```xml

<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <uses-permission android:name="android.permission.USE_BIOMETRIC" />
</manifest>
```

2. Import the package in your Dart code:

```dart
import 'package:biometric_signature/biometric_signature.dart';
```

3. Initialize the Biometric Signature instance:

```dart

final biometricSignature = BiometricSignature();
```

## Usage

This package simplifies server authentication using biometrics. The following image from Android Developers Blog illustrates the basic use case:

![biometric_signature](https://raw.githubusercontent.com/chamodanethra/biometric_signature/version-upgrade/assets/usecase.png)

When a user enrolls in biometrics, a key pair is generated. The private key is securely stored on the device, while the public key is sent to a server for registration. To authenticate, the user is prompted to use their biometrics, unlocking the private key. A cryptographic signature is then generated and sent to the server for verification. If the server successfully verifies the signature, it returns an appropriate response, authorizing the user.

## Class: BiometricSignaturePlugin

This class provides methods to manage and utilize biometric authentication for secure server interactions. It supports both Android and iOS platforms.

### `createKeys(AndroidConfig androidConfig, IosConfig iosConfig)`

Generates a new key pair (RSA 2048 or EC) for biometric authentication. The private key is securely stored on the device, and the public key is returned as a base64 encoded string. This method deletes any existing key pair before creating a new one. StrongBox support is available for compatible android devices. Secure Enclave support is available for iOS.

- **Parameters**:

- `androidConfig`: An `AndroidConfig` object containing following properties:
    - `useDeviceCredentials`: A `bool` to indicate whether Device Credentials' fallback support is needed for the compatible Android devices.
    - `signatureType`: An enum value of `AndroidSignatureType`.
- `iosConfig`: An `IosConfig` object containing following properties:
    - `useDeviceCredentials`: A `bool` to indicate whether Device Credentials' fallback support is needed.
    - `signatureType`: An enum value of `IOSSignatureType`.

- **Returns**: `String` - The base64 encoded public key.

- **Error Codes**:

- `AUTH_FAILED`: Error generating keys.
- `CANCELLED`: Timed out waiting for 30_000 ms.

### `createSignature(SignatureOptions options)`

Prompts the user for biometric authentication and generates a cryptographic signature (RSA PKCS#1v1.5 SHA-256 or EC) using the securely stored private key.

- **Parameters**:

- `options`: A `SignatureOptions` instance that specifies:
    - `payload` (required): The UTF-8 payload to sign.
    - `promptMessage` (optional): Message displayed in the biometric prompt. Default to `Authenticate`.
    - `androidOptions` (optional): An `AndroidSignatureOptions` object offering:
        - `cancelButtonText`: Overrides the cancel button label. Defaults to `Cancel`.
        - `allowDeviceCredentials`: Enables device-credential fallback on compatible Android devices.
    - `iosOptions` (optional): An `IosSignatureOptions` object offering:
        - `shouldMigrate`: Triggers migration from pre-5.x Keychain storage to Secure Enclave.

- **Returns**: `String` - The base64 encoded cryptographic signature.

- **Error Codes**:

- `INVALID_PAYLOAD`: Payload is required and must be valid UTF-8.
- `AUTH_FAILED`: Error generating the signature.
- `CANCELLED`: Timed out waiting for 30_000 ms.

### `deleteKeys()`

Deletes the existing key pair used for biometric authentication.

- **Returns**: `Bool` - `true` if the key was successfully deleted.

- **Error Codes**:

- `AUTH_FAILED`: Error deleting the biometric key

### `biometricAuthAvailable()`

Checks if biometric authentication is available on the device. On Android, it specifically checks for Biometric Strong Authenticators, which provide a higher level of security.

- **Returns**: `String` - The type of biometric authentication available (`fingerprint`, `face`, `iris`, `TouchID`, `FaceID`, or `biometric`) or a string indicating the error if no biometrics are available.

- **Possible negative returns in Android**:

- `none, BIOMETRIC_ERROR_NO_HARDWARE`: No biometric hardware available.

- `none, BIOMETRIC_ERROR_HW_UNAVAILABLE`: Biometric hardware currently unavailable.

- `none, BIOMETRIC_ERROR_NONE_ENROLLED`: No biometric credentials enrolled.

- `none, BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED`: Security update required.

- `none, BIOMETRIC_ERROR_UNSUPPORTED`: Biometric authentication is unsupported.

- `none, BIOMETRIC_STATUS_UNKNOWN`: Unknown status.

- `none, NO_BIOMETRICS`: No biometrics.

### `biometricKeyExists(checkValidity: bool)`

Checks if the biometric key pair exists on the device. Optionally, it can also verify the validity of the key by attempting to initialize a signature with it. The key will become irreversibly invalidated once the secure lock screen is disabled (reconfigured to None, Swipe or other mode which does not authenticate the user) or when the secure lock screen is forcibly reset (e.g., by a Device Administrator). Since the key requires that user authentication takes place for every use of the key, it is also irreversibly invalidated once a new biometric is enrolled or once no more biometrics are enrolled.

-   **Parameters**:
    -   `checkValidity`: A bool indicating whether to check the validity of the key by initializing a signature. Default is `false`.
-   **Returns**: `Bool` - `true` if the key pair exists (and is valid if `checkValidity` is `true`), `false` otherwise.
-   **Error Codes**:
    -   `AUTH_FAILED`: Error checking if the biometric key exists.

## Example

```dart
import 'package:flutter/material.dart';
import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/signature_options.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: Text('Biometric Signature Example')),
        body: Center(child: BiometricAuthButton()),
      ),
    );
  }
}

class BiometricAuthButton extends StatelessWidget {
  final BiometricSignature _biometricSignature = BiometricSignature();

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      child: Text('Authenticate with Biometrics'),
      onPressed: () async {
        final biometrics = await _biometricSignature
            .biometricAuthAvailable();
        if (!biometrics!.contains("none, ")) {
          try {
            final String? publicKey = await _biometricSignature
                .createKeys();
            final String? signature = await _biometricSignature.createSignature(
              SignatureOptions(
                payload: "Payload to sign",
                promptMessage: "You are Welcome!",
                androidOptions: const AndroidSignatureOptions(
                  allowDeviceCredentials: true,
                ),
                iosOptions: const IosSignatureOptions(
                  shouldMigrate: true,
                ),
              ),
            );
          } on PlatformException catch (e) {
            debugPrint(e.message);
            debugPrint(e.code);
          }
        }
      },
    );
  }
}
```
