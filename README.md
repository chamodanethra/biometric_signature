# biometric_signature

Biometric Signature is a Flutter plugin that simplifies the process of integrating biometric
authentication (fingerprint, facial, and iris recognition) into your Dart and Flutter applications.
It is designed to provide a consistent user experience across both Android and iOS platforms, with
customizable UI components and high-level abstractions for biometric signature management.

## Features

- Cross-platform support (Android and iOS)
- Fingerprint, facial, and iris recognition (based on device capabilities)
- Simple integration with Dart and Flutter applications
- Customizable UI components for signature prompts
- High-level abstractions for managing biometric signatures

## Getting Started

To get started with Biometric Signature, follow these steps:

1. Add the package to your project by including it in your `pubspec.yaml` file:

```yaml
dependencies:
  biometric_signature: ^1.0.4
```

|             | Android | iOS   |
|-------------|---------|-------|
| **Support** | SDK 23+ | 11.0+ |

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

## Example

```dart
import 'package:flutter/material.dart';
import 'package:biometric_signature/biometric_signature.dart';

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
        if (await _biometricSignature.canCheckBiometrics) {
          final biometrics = await _biometricSignature.getAvailableBiometrics();
          if (biometrics.isNotEmpty) {
            try {
              final String? signature = await _biometricSignature.createSignature(
                  options: {"promptMessage": "You are Welcome!"});
            } on PlatformException catch (e) {
              debugPrint(e.message);
              debugPrint(e.details);
            }
          }
        }
      },
    );
  }
}
```

