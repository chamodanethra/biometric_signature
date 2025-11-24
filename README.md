# biometric_signature

**Stop just unlocking the UI. Start proving the identity.**

While standard plugins like `local_auth` return a simple `true` if the user passes biometrics, `biometric_signature` generates a **cryptographic signature** using a private key stored in hardware (Secure Enclave / StrongBox).

This means even if a device is rooted or the app binary is hooked to return "true", your server will reject the request because the attacker cannot forge the cryptographic signature without the private key.

## Features

- **Cryptographic Proof:** Returns a signature (RSA/ECDSA) verifyable on your backend.
- **RSA Decryption:** Supports decrypting data using the private key stored in hardware (RSA/ECB/PKCS1Padding).
- **Hardware Security:** Uses Secure Enclave (iOS) and Keystore/StrongBox (Android).
- **Legacy Support:** Unique **Hybrid RSA** on iOS allows storing RSA keys in the Secure Enclave (wrapping them with EC), perfect for banking backends that don't support ECDSA yet.
- **Key Invalidation:** Keys are automatically destroyed if a new fingerprint/face is enrolled, preventing attackers from adding their own biometrics to bypass security.
- **Device Credentials:** Optional fallback to PIN/Pattern for broader device support.

## Security Architecture

1.  **Enrollment:** App requests keys. User authenticates. Private Key is generated inside the Hardware Security Module (HSM) and never leaves. Public Key is sent to your server.
2.  **Signing:** App requests a signature. User authenticates (FaceID/Fingerprint). The HSM signs the payload using the Private Key.
3.  **Verification:** App sends the `signature` and `payload` to your server. Server verifies them using the stored Public Key.

## Backend Verification

To ensure security, you must verify the signature on your server. Do not verify it inside the Flutter app.

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
  biometric_signature: ^8.4.0
```

|             | Android | iOS   |
|-------------|---------|-------|
| **Support** | SDK 24+ | 13.0+ |

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
import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';
import 'package:biometric_signature/signature_options.dart';
import 'package:biometric_signature/decryption_options.dart';
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

### `createKeys({ androidConfig, iosConfig, keyFormat, enforceBiometric })`

Generates a new key pair (RSA 2048 or EC) for biometric authentication. The private key is securely stored on the device, while the `KeyCreationResult` returned from this call contains a `FormattedValue` with the public key in the requested representation. StrongBox support is available for compatible Android devices and Secure Enclave support is available for iOS.

- **Parameters**:
    -`androidConfig`: An `AndroidConfig` object containing following properties:
        - `useDeviceCredentials`: A `bool` to indicate whether Device Credentials' fallback support is needed for the compatible Android devices.
        - `signatureType`: An enum value of `AndroidSignatureType`.
        - `setInvalidatedByBiometricEnrollment` *(optional)*: A `bool` to indicate whether the key should be invalidated when a new biometric is enrolled. Defaults to `true`. When set to `true`, adding a new fingerprint, face, or iris will invalidate the existing key, requiring re-enrollment. This enhances security by ensuring keys are tied to the specific biometric set at creation time.
        - `enableDecryption` *(optional)*: A `bool` to indicate whether the generated key should support decryption (RSA only). Defaults to `false`.
    - `iosConfig`: An `IosConfig` object containing following properties:
        - `useDeviceCredentials`: A `bool` to indicate whether Device Credentials' fallback support is needed.
        - `signatureType`: An enum value of `IOSSignatureType`.
        - `biometryCurrentSet` *(optional)*: A `bool` to constrain key usage to the current biometric enrollment. Defaults to `true`. When set to `true`, the key is bound to the current set of enrolled biometrics. If biometrics are changed (e.g., a new fingerprint is added or removed), the key becomes invalid, requiring re-enrollment.
    - `keyFormat` *(optional)*: A `KeyFormat` value describing how the public key should be returned. Defaults to `KeyFormat.base64` for backward compatibility.
    - `enforceBiometric` *(optional)*: A `bool` to require biometric authentication before generating the key-pair. Defaults to `false`. When set to `true`, the user will be prompted for biometric authentication (fingerprint, face, or iris) before the key-pair is generated. This ensures that the person holding the device is verified before keys are created, adding an extra layer of security for sensitive use cases.

- **Returns**: `Future<KeyCreationResult?>`. Access the formatted public key through `result.publicKey`, e.g.:

```dart
final keyResult = await biometricSignature.createKeys(keyFormat: KeyFormat.pem);
final pem = keyResult?.publicKey.asString();
final derBytes = keyResult?.publicKey.toBytes();
```

- **Error Codes**:
  - `AUTH_FAILED`: Error generating keys.

### `createSignature(SignatureOptions options)`

Prompts the user for biometric authentication and generates a cryptographic signature (RSA PKCS#1v1.5 SHA-256 or ECDSA) using the securely stored private key. The new response is a `SignatureResult` that carries both the signature and public key in the requested output format.

- **Parameters**:
  - `options`: A `SignatureOptions` instance that specifies:
    - `payload` (required): The UTF-8 payload to sign.
    - `promptMessage` (optional): Message displayed in the biometric prompt. Default to `Authenticate`.
    - `androidOptions` (optional): An `AndroidSignatureOptions` object offering:
        - `cancelButtonText`: Overrides the cancel button label. Defaults to `Cancel`.
        - `allowDeviceCredentials`: Enables device-credential fallback on compatible Android devices.
        - `subtitle`: Optional secondary text displayed under the prompt title on Android.
    - `iosOptions` (optional): An `IosSignatureOptions` object offering:
        - `shouldMigrate`: Triggers migration from pre-5.x Keychain storage to Secure Enclave.
    - `keyFormat` *(optional)*: Preferred output format (`KeyFormat.base64` by default). This is a new parameter.

- **Returns**: `Future<SignatureResult?>`. Use the `FormattedValue` helpers to obtain the representation you need:

```dart
final signatureResult = await biometricSignature.createSignature(
    SignatureOptions(
        payload: 'Payload to sign',
        keyFormat: KeyFormat.raw,
        promptMessage: 'Authenticate to Sign',
        androidOptions: const AndroidSignatureOptions(allowDeviceCredentials: false),
        iosOptions: const IosSignatureOptions(shouldMigrate: false),
    ),
);

final Uint8List rawSignature = signatureResult!.signature.toBytes();
final String base64Signature = signatureResult.signature.toBase64();
```

- **Error Codes**:
  - `INVALID_PAYLOAD`: Payload is required and must be valid UTF-8.
  - `AUTH_FAILED`: Error generating the signature.

#### Supported output formats

`KeyFormat` lets you decide how both the public key and signature are returned:

- `KeyFormat.base64` &mdash; URL/transport friendly string (default).
- `KeyFormat.pem` &mdash; PEM block with headers, using SubjectPublicKeyInfo on both platforms.
- `KeyFormat.raw` &mdash; `Uint8List` (DER bytes for public keys, raw signature bytes).
- `KeyFormat.hex` &mdash; Lowercase hexadecimal string.

Each `FormattedValue` exposes helpers such as `toBase64()`, `toBytes()`, `toHex()` and `asString()` so you can easily convert between representations.

### `decrypt(DecryptionOptions options)`

Decrypts the given payload using the private key and biometrics. This is currently supported for RSA keys only.

- **Parameters**:
  - `options`: A `DecryptionOptions` instance that specifies:
    - `payload` (required): The Base64 encoded encrypted payload to decrypt.
    - `promptMessage` (optional): Message displayed in the biometric prompt. Default to `Authenticate`.
    - `androidOptions` (optional): An `AndroidDecryptionOptions` object offering:
        - `cancelButtonText`: Overrides the cancel button label. Defaults to `Cancel`.
        - `allowDeviceCredentials`: Enables device-credential fallback on compatible Android devices.
        - `subtitle`: Optional secondary text displayed under the prompt title on Android.
    - `iosOptions` (optional): An `IosDecryptionOptions` object offering:
        - `shouldMigrate`: Triggers migration from pre-5.x Keychain storage to Secure Enclave.

- **Returns**: `Future<DecryptResult?>`. The `DecryptResult` contains the `decryptedData` string.

```dart
final decryptResult = await biometricSignature.decrypt(
    DecryptionOptions(
        payload: 'Base64 Encrypted Payload',
        promptMessage: 'Authenticate to Decrypt',
        androidOptions: const AndroidDecryptionOptions(allowDeviceCredentials: false),
        iosOptions: const IosDecryptionOptions(shouldMigrate: false),
    ),
);

final decryptedString = decryptResult?.decryptedData;
```

- **Error Codes**:
  - `INVALID_PAYLOAD`: Payload is required.
  - `AUTH_FAILED`: Error decrypting the payload.

### `deleteKeys()`

Deletes the existing key pair used for biometric authentication.

- **Returns**: `bool` - `true` if the key was successfully deleted.

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

Checks if the biometric key pair exists on the device. Optionally, it can also verify the validity of the key by attempting to initialize a signature with it. Since the key requires that user authentication takes place for every use of the key, it is also irreversibly invalidated once a new biometric is enrolled or once no more biometrics are enrolled (when `setInvalidatedByBiometricEnrollment` is `true` on Android or `biometryCurrentSet` is `true` on iOS).

-   **Parameters**:
    -   `checkValidity`: A bool indicating whether to check the validity of the key by initializing a signature. Default is `false`.
-   **Returns**: `bool` - `true` if the key pair exists (and is valid if `checkValidity` is `true`), `false` otherwise.
-   **Error Codes**:
    -   `AUTH_FAILED`: Error checking if the biometric key exists.

## Example

```dart
import 'package:biometric_signature/biometric_signature.dart';
import 'package:flutter/material.dart';

void main() => runApp(const MyApp());

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(home: Scaffold(body: BiometricDemo()));
  }
}

class BiometricDemo extends StatefulWidget {
  const BiometricDemo({super.key});

  @override
  State<BiometricDemo> createState() => _BiometricDemoState();
}

class _BiometricDemoState extends State<BiometricDemo> {
  final _biometricSignature = BiometricSignature();
  KeyCreationResult? keyResult;
  SignatureResult? signatureResult;

  Future<void> _generateKeys() async {
    keyResult = await _biometricSignature.createKeys(
      keyFormat: KeyFormat.pem,
      androidConfig: AndroidConfig(
        useDeviceCredentials: false,
        signatureType: AndroidSignatureType.RSA,
        setInvalidatedByBiometricEnrollment: true, // Key invalidated when new biometric is enrolled
        enableDecryption: true, // Enable decryption support
      ),
      iosConfig: IosConfig(
        useDeviceCredentials: false,
        signatureType: IOSSignatureType.RSA,
        biometryCurrentSet: true, // Key constrained to current biometric enrollment
      ),
      enforceBiometric: true, // Require biometric authentication before generating keys
    );
    debugPrint('Public key (${keyResult.publicKey.format.wireValue}):\n${keyResult?.publicKey.asString()}');
    setState(() {});
  }

  Future<void> _sign() async {
    signatureResult = await _biometricSignature.createSignature(
      SignatureOptions(
        payload: 'Payload to sign',
        keyFormat: KeyFormat.base64,
        promptMessage: 'Authenticate to Sign',
        androidOptions: const AndroidSignatureOptions(
          subtitle: 'Approve the login to continue',
          allowDeviceCredentials: false,
        ),
        iosOptions: const IosSignatureOptions(shouldMigrate: false),
      ),
    );
    debugPrint('Signature (${signatureResult.signature.format.wireValue}): ${signatureResult?.signature}');
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          ElevatedButton(
            onPressed: _generateKeys,
            child: const Text('Create keys (PEM)'),
          ),
          const SizedBox(height: 12),
          ElevatedButton(
            onPressed: _sign,
            child: const Text('Sign payload (RAW)'),
          ),
          if (signatureResult != null) ...[
            const SizedBox(height: 16),
            Text('Signature HEX:\n${signatureResult!.signature.toHex()}'),
          ],
        ],
      ),
    );
  }
}
```
