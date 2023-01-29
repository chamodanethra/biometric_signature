# biometric_signature

This Flutter plugin provides an easy way to integrate cryptographic signing with biometric authentication.

On supported devices, this includes biometric signing with
fingerprint or facial recognition or iris scanning.

|             | Android | iOS   |
|-------------|---------|-------|
| **Support** | SDK 23+ | 11.0+ |

## Getting started

To use this plugin, add biometric_signature as a dependency in your pubspec.yaml file.


## iOS Integration

This plugin works with Touch ID **or** Face ID. To use Face ID in available devices,
you need to add:

```xml

<key>NSFaceIDUsageDescription</key>
<string>This app is using FaceID for authentication</string>
```

to your Info.plist file.


## Android Integration

### Activity Changes

This plugin requires the use of a FragmentActivity as opposed to Activity. This can be easily done
by switching to use FlutterFragmentActivity as opposed to FlutterActivity in your manifest or your
own Activity class if you are extending the base class.


### Permissions

Update your project's `AndroidManifest.xml` file to include the
`USE_BIOMETRIC` permission.

```xml

<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <uses-permission android:name="android.permission.USE_BIOMETRIC" />
</manifest>
```

**Checkout the Example section for an implementation**

