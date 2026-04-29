# biometric_signature

**Stop just unlocking the UI. Start proving the identity.**

Standard biometric integrations typically return only a boolean indicating whether authentication succeeded.
`biometric_signature` provides a complete biometric solution:

1.  **Cryptographic Proof (Core Feature):** Generates a **verifiable cryptographic signature** using a private key stored in hardware (Secure Enclave / StrongBox). This allows your backend to mathematically verify the user's identity, preventing replay attacks and API hooks.
2.  **Simple Authentication:** Supports standard biometric prompts (returning success/failure) for local UI gating or quick re-authentication, with full support for Android biometric strength levels and device credentials.

Even if an attacker bypasses or hooks biometric APIs, your backend will still reject the request because **the attacker cannot forge a hardware-backed signature without the private key**.

## Features

- **Cryptographic Proof Of Identity:** Hardware-backed RSA (Android) or ECDSA (all platforms) signatures that your backend can independently verify.
- **Decryption Support:** 
  - **RSA**: RSA/ECB/PKCS1Padding (Android native, iOS/macOS via wrapped software key)
  - **EC**: ECIES (`eciesEncryptionStandardX963SHA256AESGCM`)
- **Hardware Security:** Uses Secure Enclave (iOS/macOS) and Keystore/StrongBox (Android).
- **Hybrid Architectures:**
  - **Android Hybrid EC:** Hardware EC signing + software ECIES decryption. Software EC private key is AES-wrapped using a Keystore/StrongBox AES-256 master key that requires biometric authentication for every unwrap.
  - **iOS/macOS Hybrid RSA:** Software RSA key for **both signing and decryption**, wrapped using ECIES with Secure Enclave EC public key. Hardware EC is only used for wrapping/unwrapping.
- **Named Key Aliases:** Manage multiple independent key pairs per app (e.g., one for auth, one for payment signing) via optional `keyAlias` parameter.
- **Key Overwrite Protection:** Prevent accidental key replacement with `failIfExists` option.
- **Custom Fallback Options (Android 15+):** Show custom buttons (password, QR code, etc.) on the biometric prompt via `fallbackOptions`.
- **Key Invalidation:** Keys can be bound to biometric enrollment state (fingerprint/Face ID changes).
- **Device Credentials:** Optional PIN/Pattern/Password fallback on Android.
- **Simple Prompt (No Crypto):** Verify user presence without key operations. Supports device-credential fallback and Android biometric strength selection.


## Security Architecture

### Key Modes

The plugin supports different operational modes depending on the platform:

#### Android

Android supports three key modes:

1. **RSA Mode** (`SignatureType.rsa`):
   - Hardware-backed RSA-2048 signing (Keystore/StrongBox)
   - Optional RSA decryption (PKCS#1 padding)
   - Private key never leaves secure hardware

2. **EC Signing-Only** (`SignatureType.ecdsa`, `enableDecryption: false`):
   - Hardware-backed P-256 key in Keystore/StrongBox
   - ECDSA signing only
   - No decryption support

3. **Hybrid EC Mode** (`SignatureType.ecdsa`, `enableDecryption: true`):
   - Hardware EC key for signing
   - Software EC key for ECIES decryption
   - Software EC private key encrypted using AES-256 GCM master key (Keystore/StrongBox)
   - Per-operation biometric authentication required for decryption

#### iOS / macOS

Apple platforms support two key modes (Secure Enclave only supports EC keys natively):

1. **EC Mode** (`SignatureType.ecdsa`):
   - Hardware-backed P-256 key in Secure Enclave
   - ECDSA signing
   - Native ECIES decryption (`eciesEncryptionStandardX963SHA256AESGCM`)
   - Single key for both operations

2. **RSA Mode** (`SignatureType.rsa`) - Hybrid Architecture:
   - Software RSA-2048 key for **both signing and decryption**
   - RSA private key wrapped using ECIES with Secure Enclave EC public key
   - Hardware EC key is **only** used for wrapping/unwrapping the RSA key
   - Wrapped RSA key stored in Keychain as `kSecClassGenericPassword`
   - Per-operation biometric authentication required to unwrap RSA key



### Workflow Overview

1.  **Enrollment**

    User authenticates → hardware generates a signing key.

    Hybrid modes additionally generate a software decryption key, which is then encrypted using secure hardware.
2.  **Signing** 

    Biometric prompt is shown

    Hardware unlocks the signing key, and a verifiable signature is produced.
3.  **Decryption**

    A biometric prompt is shown again.

    Hybrid modes unwrap the software private key using hardware-protected AES-GCM, then decrypt the payload.
4.  **Backend Verification** 

    The backend verifies signatures using the registered public key.

    Verification **must not** be performed on the client.



## Backend Verification

Perform verification on the server. Below are reference implementations.

### Node.js
```javascript
const crypto = require('crypto');

function verifySignature(publicKeyPem, payload, signatureBase64) {
    const verify = crypto.createVerify('SHA256');
    verify.update(payload); // The original string you sent to the plugin
    verify.end();

    // Returns true if valid
    return verify.verify(publicKeyPem, Buffer.from(signatureBase64, 'base64'));
}
```
### Python
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

def verify_signature(public_key_pem_str, payload_str, signature_base64_str):
    public_key = serialization.load_pem_public_key(public_key_pem_str.encode())
    signature = base64.b64decode(signature_base64_str)
    
    try:
        # Assuming RSA (For EC, use ec.ECDSA(hashes.SHA256()))
        public_key.verify(
            signature,
            payload_str.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
```

### Go
```go
import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func verify(pubPemStr, payload, sigBase64 string) error {
	block, _ := pem.Decode([]byte(pubPemStr))
	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	rsaPub := pub.(*rsa.PublicKey)

	hashed := sha256.Sum256([]byte(payload))
	sig, _ := base64.StdEncoding.DecodeString(sigBase64)

	return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], sig)
}
```

## Getting Started

To get started with Biometric Signature, follow these steps:

1. Add the package to your project by including it in your `pubspec.yaml` file:

```yaml
dependencies:
  biometric_signature: ^11.1.0
```

|             | Android | iOS   | macOS  | Windows |
|-------------|---------|-------|--------|--------|
| **Support** | SDK 23+ | 13.0+ | 10.15+ | 10+    |

Minimum Flutter SDK: `3.24.5`.

Android builds must compile with Android SDK 36 or newer.

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

This plugin requires the use of a `FragmentActivity` instead of `Activity`. Update your `MainActivity.kt` to extend `FlutterFragmentActivity`:

```kotlin
import io.flutter.embedding.android.FlutterFragmentActivity

class MainActivity : FlutterFragmentActivity() {
}
```

#### Permissions

Update your project's `AndroidManifest.xml` file to include the
`USE_BIOMETRIC` permission.

```xml

<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <uses-permission android:name="android.permission.USE_BIOMETRIC" />
</manifest>
```

### macOS Integration

This plugin works with Touch ID on supported Macs. To use Touch ID, you need to:

1. Add the required entitlements to your macOS app.

Open your macOS project's entitlements file (typically located at `macos/Runner/DebugProfile.entitlements` and `macos/Runner/Release.entitlements`) and ensure it includes:

```xml
<key>com.apple.security.device.usb</key>
<false/>
<key>com.apple.security.device.bluetooth</key>
<false/>
<key>keychain-access-groups</key>
<array>
    <string>$(AppIdentifierPrefix)com.yourdomain.yourapp</string>
</array>
```

Replace `com.yourdomain.yourapp` with your actual bundle identifier.

2. Ensure CocoaPods is properly configured in your `macos/Podfile`. The plugin requires macOS 10.15 or later:

```ruby
platform :osx, '10.15'
```

### Windows Integration

### Windows Integration

This plugin uses **Windows Hello** (`Windows.Security.Credentials.KeyCredentialManager`) for biometric authentication on Windows 10 and later. Keys are typically backed by the device's **TPM (Trusted Platform Module)** for hardware-grade security.

**Platform Limitations:**
- **Key Type**: Windows Hello only supports **RSA-2048** keys (ECDSA requests are automatically promoted to RSA).
- **Authentication**: Windows Hello **always authenticates** during key creation (`enforceBiometric` is effectively always `true`).
- **Configuration**: `setInvalidatedByBiometricEnrollment` and `useDeviceCredentials` arguments are ignored on this platform.
- **Decryption**: **Not supported**. The Windows Hello API is designed primarily for authentication (signing) and does not expose general decryption capabilities for these keys.

No additional configuration is required. The plugin will automatically use Windows Hello when available.

### Common Setup

1. Import the package in your Dart code:

```dart
import 'package:biometric_signature/biometric_signature.dart';
```

2. Initialize the Biometric Signature instance:

```dart

final biometricSignature = BiometricSignature();
```

## Usage

This package simplifies server authentication using biometrics. The following image from Android Developers Blog illustrates the basic use case:

![biometric_signature](https://raw.githubusercontent.com/chamodanethra/biometric_signature/main/assets/usecase.png)

When a user enrolls in biometrics, a key pair is generated. The private key is securely stored on the device, while the public key is sent to a server for registration. To authenticate, the user is prompted to use their biometrics, unlocking the private key. A cryptographic signature is then generated and sent to the server for verification. If the server successfully verifies the signature, it returns an appropriate response, authorizing the user.

### Biometric Decryption

The plugin also supports secure decryption, ensuring that sensitive data transmitted from the server can only be accessed by the authenticated user on their specific device.

![Biometric Decryption Lifecycle](https://raw.githubusercontent.com/chamodanethra/biometric_signature/main/assets/usecase-2.jpeg)

1.  **Key Creation**: The device generates a key pair (EC or RSA) in secure hardware.
2.  **Registration**: The public key is sent to the backend server.
3.  **Encryption**: The server encrypts the sensitive payload using the public key.
4.  **Authentication**: The encrypted payload is sent to the device. The user must authenticate biometrically to proceed.
5.  **Decryption**: Once authenticated, the secure hardware uses the private key to decrypt the payload, revealing the plaintext data to the app.

## Class: BiometricSignaturePlugin

This class provides methods to manage and utilize biometric authentication for secure server interactions. It supports both Android and iOS platforms.

### `createKeys({ keyAlias, config, keyFormat, promptMessage })`

Generates a new key pair (RSA 2048 or EC) for biometric authentication. The private key is securely stored on the device.

- **Parameters**:
  - `keyAlias`: Optional name for this key pair. Different aliases create independent key pairs. When `null`, the default alias is used.
  - `config`: `CreateKeysConfig` with platform options (see below)
  - `keyFormat`: Output format (`KeyFormat.base64`, `pem`, `hex`)
  - `promptMessage`: Custom authentication prompt message

- **Returns**: `Future<KeyCreationResult>`.
  - `publicKey`: The formatted public key string (Base64 or PEM).
  - `code`: `BiometricError` code (e.g., `success`, `userCanceled`, `keyAlreadyExists`).
  - `error`: Descriptive error message.

#### CreateKeysConfig Options

| Option | Platforms | Description |
|--------|-----------|-------------|
| `signatureType` | Android/iOS/macOS | `SignatureType.rsa` or `SignatureType.ecdsa` |
| `enforceBiometric` | Android/iOS/macOS | Require biometric during key creation |
| `setInvalidatedByBiometricEnrollment` | Android/iOS/macOS | Invalidate key on biometric changes |
| `useDeviceCredentials` | Android/iOS/macOS | Allow PIN/passcode fallback |
| `enableDecryption` | Android | Enable decryption capability |
| `failIfExists` | All | Fail with `keyAlreadyExists` if key already exists |
| `fallbackOptions` | Android 15+ | Custom fallback buttons on biometric prompt (see [Custom Fallback Options](#custom-fallback-options-android-15)) |
| `promptSubtitle` | Android | Subtitle for biometric prompt |
| `promptDescription` | Android | Description for biometric prompt |
| `cancelButtonText` | Android | Cancel button text |

```dart
final result = await biometricSignature.createKeys(
  keyAlias: 'payment_key',  // Optional: named alias
  keyFormat: KeyFormat.pem,
  promptMessage: 'Authenticate to create keys',
  config: CreateKeysConfig(
    signatureType: SignatureType.rsa,
    enforceBiometric: true,
    setInvalidatedByBiometricEnrollment: true,
    useDeviceCredentials: false,
    enableDecryption: true, // Android only
    failIfExists: true,     // Prevent overwriting existing key
  ),
);

if (result.code == BiometricError.success) {
   print('Public Key: ${result.publicKey}');
} else if (result.code == BiometricError.keyAlreadyExists) {
   print('Key already exists for this alias');
}
```

### `createSignature({ payload, keyAlias, config, signatureFormat, keyFormat, promptMessage })`

Prompts the user for biometric authentication and generates a cryptographic signature.

- **Parameters**:
  - `payload`: The data to sign
  - `keyAlias`: Which key to sign with. Defaults to the default alias.
  - `config`: `CreateSignatureConfig` with platform options
  - `signatureFormat`: Output format for signature
  - `keyFormat`: Output format for public key
  - `promptMessage`: Custom authentication prompt

#### CreateSignatureConfig Options

| Option | Platforms | Description |
|--------|-----------|-------------|
| `allowDeviceCredentials` | Android | Allow PIN/pattern fallback |
| `fallbackOptions` | Android 15+ | Custom fallback buttons on biometric prompt (see [Custom Fallback Options](#custom-fallback-options-android-15)) |
| `promptSubtitle` | Android | Subtitle for biometric prompt |
| `promptDescription` | Android | Description for biometric prompt |
| `cancelButtonText` | Android | Cancel button text |
| `shouldMigrate` | iOS | Migrate from legacy keychain storage |

- **Returns**: `Future<SignatureResult>`.
  - `signature`: The signed payload.
  - `publicKey`: The public key.
  - `code`: `BiometricError` code.
  - `selectedFallbackIndex` / `selectedFallbackText`: Populated when `code == BiometricError.fallbackSelected`.

```dart
final result = await biometricSignature.createSignature(
  payload: 'Data to sign',
  keyAlias: 'payment_key',  // Optional: use named key
  promptMessage: 'Please authenticate',
  signatureFormat: SignatureFormat.base64,
  keyFormat: KeyFormat.base64,
  config: CreateSignatureConfig(
    allowDeviceCredentials: false,
  ),
);
```

### `decrypt({ payload, payloadFormat, keyAlias, config, promptMessage })`

Decrypts the given payload using the private key and biometrics.

- **Parameters**:
  - `payload`: The encrypted data
  - `payloadFormat`: Format of encrypted data (`PayloadFormat.base64`, `hex`)
  - `keyAlias`: Which key to decrypt with. Defaults to the default alias.
  - `config`: `DecryptConfig` with platform options
  - `promptMessage`: Custom authentication prompt

#### DecryptConfig Options

| Option | Platforms | Description |
|--------|-----------|-------------|
| `allowDeviceCredentials` | Android | Allow PIN/pattern fallback |
| `fallbackOptions` | Android 15+ | Custom fallback buttons on biometric prompt (see [Custom Fallback Options](#custom-fallback-options-android-15)) |
| `promptSubtitle` | Android | Subtitle for biometric prompt |
| `promptDescription` | Android | Description for biometric prompt |
| `cancelButtonText` | Android | Cancel button text |
| `shouldMigrate` | iOS | Migrate from legacy keychain storage |

> **Note**: Decryption is not supported on Windows.

- **Returns**: `Future<DecryptResult>`.
  - `decryptedData`: The plaintext string.
  - `code`: `BiometricError` code.
  - `selectedFallbackIndex` / `selectedFallbackText`: Populated when `code == BiometricError.fallbackSelected`.

```dart
final result = await biometricSignature.decrypt(
  payload: encryptedBase64,
  payloadFormat: PayloadFormat.base64,
  keyAlias: 'payment_key',  // Optional: use named key
  promptMessage: 'Authenticate to decrypt',
  config: DecryptConfig(
    allowDeviceCredentials: false,
  ),
);
```

### `deleteKeys({ keyAlias })`

Deletes biometric key material for a specific alias from the device's secure storage.

- **Parameters**:
  - `keyAlias`: Which key to delete. When `null`, deletes the default alias only. Other aliases are not affected.

- **Returns**: `Future<bool>`.
  - `true`: Keys were successfully deleted, or no keys existed (idempotent).
  - `false`: Deletion failed due to a system error.

> **Note**: This operation is idempotent—calling `deleteKeys()` when no keys exist will still return `true`. This allows safe "logout" or "reset" flows without checking key existence first.

```dart
// Delete a specific named key
final deleted = await biometricSignature.deleteKeys(keyAlias: 'payment_key');

// Delete the default key
final defaultDeleted = await biometricSignature.deleteKeys();
```

### `deleteAllKeys()`

Deletes all biometric key material across all aliases. This is a destructive operation — use `deleteKeys()` with a specific alias for targeted deletion.

- **Returns**: `Future<bool>`.
  - `true`: All keys were successfully deleted.
  - `false`: Deletion failed due to a system error.

```dart
final deleted = await biometricSignature.deleteAllKeys();
if (deleted) {
  print('All biometric keys removed across all aliases');
}
```


### `biometricAuthAvailable()`

Checks if biometric authentication is available on the device and returns a structured response.

- **Returns**: `Future<BiometricAvailability>`.
  - `canAuthenticate`: `bool` indicating if auth is possible.
  - `hasEnrolledBiometrics`: `bool` indicating if user has enrolled biometrics.
  - `availableBiometrics`: `List<BiometricType>` (e.g., `fingerprint`, `face`).
  - `reason`: String explanation if unavailable.

```dart
final availability = await biometricSignature.biometricAuthAvailable();
if (availability.canAuthenticate) {
  print('Biometrics available: ${availability.availableBiometrics}');
} else {
  print('Not available: ${availability.reason}');
}
```

### `getKeyInfo({ keyAlias, checkValidity, keyFormat })`

Retrieves detailed information about existing biometric keys without prompting for authentication.

- **Parameters**:
  - `keyAlias`: Which key to query. Defaults to the default alias.
  - `checkValidity`: Whether to verify the key hasn't been invalidated by biometric changes. Default is `false`.
  - `keyFormat`: Output format for public keys (`KeyFormat.base64`, `pem`, `hex`). Default is `base64`.
- **Returns**: `Future<KeyInfo>`.
  - `exists`: Whether any biometric key exists.
  - `isValid`: Key validity status (only populated when `checkValidity: true`).
  - `algorithm`: `"RSA"` or `"EC"`.
  - `keySize`: Key size in bits (e.g., 2048, 256).
  - `isHybridMode`: Whether using hybrid signing/decryption keys.
  - `publicKey`: The signing public key.
  - `decryptingPublicKey`: Decryption key (hybrid mode only).

```dart
final info = await biometricSignature.getKeyInfo(
  keyAlias: 'payment_key',  // Optional: query named key
  checkValidity: true,
  keyFormat: KeyFormat.pem,
);

if (info.exists && (info.isValid ?? true)) {
  print('Algorithm: ${info.algorithm}, Size: ${info.keySize}');
  print('Hybrid Mode: ${info.isHybridMode}');
}
```

### `biometricKeyExists({ keyAlias, checkValidity })`

Convenience method that wraps `getKeyInfo()` and returns a simple boolean.

- **Parameters**:
  - `keyAlias`: Which key to check. Defaults to the default alias.
  - `checkValidity`: Whether to check key validity. Default is `false`.
- **Returns**: `Future<bool>` - `true` if key exists and is valid.

```dart
final exists = await biometricSignature.biometricKeyExists(
  keyAlias: 'payment_key',
  checkValidity: true,
);
```

### `simplePrompt({ promptMessage, config })`

Performs biometric authentication without performing any cryptographic operation. Useful for quick re-authentication or gating sensitive UI.

#### SimplePromptConfig Options

| Option | Platforms | Description |
|--------|-----------|-------------|
| `subtitle` | Android | Subtitle for biometric prompt |
| `description` | Android | Description for biometric prompt |
| `cancelButtonText` | Android | Cancel button text |
| `allowDeviceCredentials` | Android/iOS/macOS | Allow PIN/pattern/passcode fallback |
| `biometricStrength` | Android | `BiometricStrength.strong` or `BiometricStrength.weak` |
| `fallbackOptions` | Android 15+ | Custom fallback buttons on biometric prompt (see [Custom Fallback Options](#custom-fallback-options-android-15)) |

```dart
final result = await biometricSignature.simplePrompt(
  promptMessage: 'Verify your identity',
  config: SimplePromptConfig(
    subtitle: 'Access secure features',
    allowDeviceCredentials: true,
    biometricStrength: BiometricStrength.strong,
  ),
);

if (result.success == true) {
  // Authenticated
} else if (result.code == BiometricError.fallbackSelected) {
  print('User chose: ${result.selectedFallbackText}');
} else {
  print('Failed: ${result.code} - ${result.error}');
}
```

---

## Custom Fallback Options (Android 15+)

On Android 15 and later, you can display custom fallback buttons on the biometric prompt using `BiometricFallbackOption`. These replace the default cancel button and allow users to choose alternative authentication methods.

### `BiometricFallbackOption`

| Property | Type | Description |
|----------|------|-------------|
| `text` | `String?` | The label displayed on the fallback button |
| `iconName` | `String?` | Icon type: `"password"`, `"qr_code"`, `"account"`, or `"generic"` (default) |

### Usage

```dart
import 'dart:io' show Platform;

// Define fallback options (Android only)
final fallbackOptions = Platform.isAndroid
    ? [
        BiometricFallbackOption(text: 'Use Password', iconName: 'password'),
        BiometricFallbackOption(text: 'Scan QR Code', iconName: 'qr_code'),
      ]
    : null;

// Pass to any config class
final result = await biometricSignature.createSignature(
  payload: 'Data to sign',
  promptMessage: 'Authenticate',
  config: CreateSignatureConfig(
    fallbackOptions: fallbackOptions,
  ),
);

// Handle the result
if (result.code == BiometricError.success) {
  print('Signature: ${result.signature}');
} else if (result.code == BiometricError.fallbackSelected) {
  print('Fallback selected: ${result.selectedFallbackText} '
      '(index: ${result.selectedFallbackIndex})');
}
```

> **Note**: On iOS, macOS, and Windows, `fallbackOptions` is ignored. On Android versions below 15, the standard biometric prompt is shown instead.

---

## Migration Guide

This section covers breaking changes and migration steps for upgrading between major versions. It assumes familiarity with the plugin’s core concepts (key creation, signing, biometric availability).

### Migrating from v5/v6 to v7

**v7.0.0** replaced the legacy map-based `createSignature()` API with typed `SignatureOptions`.

#### `createSignature()` API Change

**Before (v5/v6):**
```dart
final signature = await biometricSignature.createSignature(
  options: {
    'payload': 'data to sign',
    'promptMessage': 'Authenticate',
    'cancelButtonText': 'Cancel',          // Android
    'allowDeviceCredentials': 'false',     // Android
    'shouldMigrate': 'true',               // iOS
  },
);
```

**After (v7):**
```dart
final signature = await biometricSignature.createSignature(
  SignatureOptions(
    payload: 'data to sign',
    promptMessage: 'Authenticate',
    androidOptions: AndroidSignatureOptions(
      cancelButtonText: 'Cancel',
      allowDeviceCredentials: false,
    ),
    iosOptions: IosSignatureOptions(
      shouldMigrate: true,
    ),
  ),
);
```

> [!NOTE]
> v7 provided a temporary helper `createSignatureFromLegacyOptions()` for migration, but this was removed in v8.

---

### Migrating from v7 to v8

**v8.0.0** introduced structured return types and configurable key/signature formats.

#### Return Types Changed

**Before (v7):** Methods returned `String?` or `bool?`.

**After (v8):** Methods return structured result objects with metadata.

| Method | v7 Return Type | v8 Return Type |
|--------|---------------|----------------|
| `createKeys()` | `String?` | `KeyCreationResult?` |
| `createSignature()` | `String?` | `SignatureResult?` |

#### `createKeys()` Changes

**Before (v7):**
```dart
final publicKey = await biometricSignature.createKeys(
  androidConfig: AndroidConfig(useDeviceCredentials: false),
  iosConfig: IosConfig(useDeviceCredentials: false),
);
// publicKey is a String?
```

**After (v8):**
```dart
final result = await biometricSignature.createKeys(
  androidConfig: AndroidConfig(useDeviceCredentials: false),
  iosConfig: IosConfig(useDeviceCredentials: false),
  keyFormat: KeyFormat.pem,  // NEW: choose output format
);
// result.publicKey, result.algorithm, result.keySize available
```

#### `createSignature()` Changes

**Before (v7):**
```dart
final signature = await biometricSignature.createSignature(options);
// signature is a String?
```

**After (v8):**
```dart
final result = await biometricSignature.createSignature(
  SignatureOptions(
    payload: 'data',
    promptMessage: 'Sign',
    keyFormat: KeyFormat.base64,  // NEW: output format
  ),
);
// result.signature, result.publicKey available
```

#### New Features in v8

- **Key Formats:** `KeyFormat.base64`, `KeyFormat.pem`, `KeyFormat.hex`, `KeyFormat.raw`
- **enforceBiometric:** Require biometric authentication during key creation
- **setInvalidatedByBiometricEnrollment:** Bind keys to biometric enrollment state
- **Decryption support (v8.4+):** RSA and ECIES decryption via `decrypt()`
- **macOS support (v8.5):** Touch ID support on Mac via `MacosConfig`

---

### Migrating from v8 to v9

**v9.0.0** is a major refactoring that unifies platform configurations and migrates to Pigeon for type-safe platform communication.

#### Key Architecture Changes

1. **Pigeon Migration:** All platform communication now uses strongly-typed Pigeon interfaces
2. **Unified Config Objects:** Platform-specific configs (`AndroidConfig`, `IosConfig`, `MacosConfig`) consolidated into single config classes
3. **Standardized Error Handling:** All methods return result objects with `BiometricError` enum codes
4. **New Methods:** `getKeyInfo()` for detailed key inspection, `deleteKeys()` returns `Future<bool>`

#### `createKeys()` Changes

**Before (v8):**
```dart
final result = await biometricSignature.createKeys(
  androidConfig: AndroidConfig(
    useDeviceCredentials: false,
    signatureType: AndroidSignatureType.RSA,
    enforceBiometric: true,
    setInvalidatedByBiometricEnrollment: true,
    enableDecryption: true,
  ),
  iosConfig: IosConfig(
    useDeviceCredentials: false,
    signatureType: IOSSignatureType.RSA,
    enforceBiometric: true,
    setInvalidatedByBiometricEnrollment: true,
  ),
  macosConfig: MacosConfig(
    useDeviceCredentials: false,
    signatureType: MacosSignatureType.RSA,
  ),
  keyFormat: KeyFormat.pem,
);
```

**After (v9):**
```dart
final result = await biometricSignature.createKeys(
  keyFormat: KeyFormat.pem,
  promptMessage: 'Authenticate to create keys',  // NEW: top-level
  config: CreateKeysConfig(
    signatureType: SignatureType.rsa,            // Unified enum
    enforceBiometric: true,
    setInvalidatedByBiometricEnrollment: true,
    useDeviceCredentials: false,
    enableDecryption: true,                      // Android only
    promptSubtitle: 'Subtitle',                  // Android only
    promptDescription: 'Description',            // Android only
    cancelButtonText: 'Cancel',                  // Android only
  ),
);

if (result.code == BiometricError.success) {
  print('Public Key: ${result.publicKey}');
} else {
  print('Error: ${result.code} - ${result.error}');
}
```

#### `createSignature()` Changes

**Before (v8):**
```dart
final result = await biometricSignature.createSignature(
  SignatureOptions(
    payload: 'data to sign',
    promptMessage: 'Authenticate',
    keyFormat: KeyFormat.base64,
    androidOptions: AndroidSignatureOptions(
      cancelButtonText: 'Cancel',
      allowDeviceCredentials: false,
    ),
    iosOptions: IosSignatureOptions(
      shouldMigrate: true,
    ),
  ),
);
```

**After (v9):**
```dart
final result = await biometricSignature.createSignature(
  payload: 'data to sign',                        // Top-level parameter
  promptMessage: 'Authenticate',                  // Top-level parameter
  signatureFormat: SignatureFormat.base64,        // NEW: separate format
  keyFormat: KeyFormat.base64,                    // Public key format
  config: CreateSignatureConfig(
    allowDeviceCredentials: false,                // Android
    promptSubtitle: 'Subtitle',                   // Android
    promptDescription: 'Description',             // Android
    cancelButtonText: 'Cancel',                   // Android
    shouldMigrate: true,                          // iOS
  ),
);

if (result.code == BiometricError.success) {
  print('Signature: ${result.signature}');
}
```

#### `biometricAuthAvailable()` Changes

**Before (v8):**
```dart
final availability = await biometricSignature.biometricAuthAvailable();
// Returns String? like "fingerprint", "face", "none", etc.
```

**After (v9):**
```dart
final availability = await biometricSignature.biometricAuthAvailable();
// Returns BiometricAvailability object

if (availability.canAuthenticate ?? false) {
  print('Biometrics available: ${availability.availableBiometrics}');
  // availableBiometrics is List<BiometricType>
} else {
  print('Not available: ${availability.reason}');
}
```

#### `decrypt()` Changes (v8.4+ → v9)

**Before (v8):**
```dart
final result = await biometricSignature.decrypt(
  DecryptionOptions(
    payload: encryptedBase64,
    promptMessage: 'Decrypt',
    androidOptions: AndroidDecryptionOptions(
      allowDeviceCredentials: false,
    ),
    iosOptions: IosDecryptionOptions(
      shouldMigrate: true,
    ),
  ),
);
```

**After (v9):**
```dart
final result = await biometricSignature.decrypt(
  payload: encryptedBase64,
  payloadFormat: PayloadFormat.base64,    // NEW: explicit format
  promptMessage: 'Decrypt',
  config: DecryptConfig(
    allowDeviceCredentials: false,        // Android
    shouldMigrate: true,                  // iOS
  ),
);

if (result.code == BiometricError.success) {
  print('Decrypted: ${result.decryptedData}');
}
```

#### New `getKeyInfo()` Method

v9 introduces `getKeyInfo()` for inspecting existing keys without authentication:

```dart
final info = await biometricSignature.getKeyInfo(
  checkValidity: true,      // Check if key was invalidated
  keyFormat: KeyFormat.pem,
);

if (info.exists ?? false) {
  print('Algorithm: ${info.algorithm}');      // "RSA" or "EC"
  print('Key Size: ${info.keySize}');         // 2048, 256, etc.
  print('Hybrid Mode: ${info.isHybridMode}'); // Separate decrypt key?
  print('Valid: ${info.isValid}');            // Not invalidated?
}
```

> [!TIP]
> `biometricKeyExists()` is now a convenience wrapper around `getKeyInfo()`.

#### Summary of v9 Breaking Changes

| Change | v8 | v9 |
|--------|----|----|
| Platform configs | `AndroidConfig`, `IosConfig`, `MacosConfig` | `CreateKeysConfig`, `CreateSignatureConfig`, `DecryptConfig` |
| Signature type enum | `AndroidSignatureType.RSA` | `SignatureType.rsa` |
| Error handling | Check for `null` | Check `result.code == BiometricError.success` |
| biometricAuthAvailable | Returns `String?` | Returns `BiometricAvailability` |
| Platform communication | MethodChannel with maps | Pigeon with typed classes |
| Windows support | ❌ | ✅ (v9.0.0+) |

#### Import Changes

**Before (v8):**
```dart
import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';
import 'package:biometric_signature/signature_options.dart';
```

**After (v9):**
```dart
import 'package:biometric_signature/biometric_signature.dart';
// All types exported from single import
```

### Migrating from v9 to v10

**v10.0.0** refines error handling and introduces non-cryptographic authentication.

#### Breaking: `BiometricError` Changes

**Values Added**: New error codes were added to cover more edge cases:
-   `BiometricError.securityUpdateRequired`
-   `BiometricError.notSupported`
-   `BiometricError.systemCanceled`
-   `BiometricError.promptError`
-   **Impact**: If you use exhaustive switch statements (e.g., in Dart 3.0+), you must add cases for these new values.

#### New Feature: `simplePrompt()`

v10 adds `simplePrompt()` for scenarios where you only need to verify the user's presence without cryptographic operations. See the [Usage](#usage) section for details.

---

### Migrating from v10 to v11

**v11.0.0** adds named key aliases, key overwrite protection, custom fallback options, and internal architecture improvements.

#### New: Named Key Aliases

All key operations now accept an optional `keyAlias` parameter:

```dart
// Before (v10.2) — single default key
final result = await biometricSignature.createKeys(...);

// After (v11.0) — multiple named keys
final authKey = await biometricSignature.createKeys(keyAlias: 'auth', ...);
final paymentKey = await biometricSignature.createKeys(keyAlias: 'payment', ...);
```

Methods updated: `createKeys`, `createSignature`, `decrypt`, `deleteKeys`, `getKeyInfo`, `biometricKeyExists`.

#### New: Key Overwrite Protection

```dart
final result = await biometricSignature.createKeys(
  keyAlias: 'payment',
  config: CreateKeysConfig(failIfExists: true),
);

if (result.code == BiometricError.keyAlreadyExists) {
  // Key already exists — handle accordingly
}
```

#### New: `deleteAllKeys()`

```dart
// Delete all keys across all aliases
await biometricSignature.deleteAllKeys();
```

#### New: Custom Fallback Options (Android 15+)

All config classes now support `fallbackOptions`. See [Custom Fallback Options](#custom-fallback-options-android-15) for details.

#### New Breaking: `BiometricError` Values

- `BiometricError.keyAlreadyExists` — returned when `failIfExists: true` and key exists.
- `BiometricError.fallbackSelected` — returned when user taps a custom fallback button. Check `selectedFallbackIndex` and `selectedFallbackText` on the result object.
- **Impact**: If you use exhaustive switch statements (e.g., in Dart 3.0+), you must add cases for these new values.
