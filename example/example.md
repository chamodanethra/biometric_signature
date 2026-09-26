# biometric_signature examples

A short tour of the API. The full [API Explorer](https://github.com/chamodanethra/biometric_signature/tree/main/example)
(this `example/` app) exercises every method, option, format and error code, and the
[scenario apps](#scenario-apps) show complete flows with a mock server.

```dart
import 'package:biometric_signature/biometric_signature.dart';

final biometric = BiometricSignature();
```

Every method returns its errors in `result.code` (a `BiometricError`) and a human-readable
`result.error`; nothing is thrown for authentication or key errors.

## 1. Check the device

```dart
final availability = await biometric.biometricAuthAvailable();
if (availability.canAuthenticate != true) {
  // availability.reason says why; availability.availableBiometrics lists
  // the sensor types.
}

// Android: authoritative. iOS/macOS: true means "set or indeterminate".
// Windows: whether Windows Hello (with a PIN) is available.
final hasScreenLock = await biometric.isDeviceLockSet();
```

## 2. Create a key under an alias

```dart
final created = await biometric.createKeys(
  keyAlias: 'login', // independent key pairs per alias; use [a-z0-9_-]
  keyFormat: KeyFormat.pem,
  promptMessage: 'Set up biometric sign-in',
  config: CreateKeysConfig(
    signatureType: SignatureType.ecdsa, // Windows always uses RSA-2048
    setInvalidatedByBiometricEnrollment: true,
    useDeviceCredentials: false,
    failIfExists: true, // keyAlreadyExists instead of replacing a key
  ),
);

if (created.code == BiometricError.success) {
  // SubjectPublicKeyInfo in the requested format. Register it with your
  // server — this is the key it will verify against.
  final publicKeyPem = created.publicKey!;
}
```

`publicKey` is SPKI DER (base64, PEM or hex) on every platform. `publicKeyBytes` is not: it is
SPKI on Android and Windows but the raw EC point or PKCS#1 RSA key on iOS/macOS, so verify
against `publicKey`.

For a key that signs without any prompt (device binding only, no user presence), pass
`requireAuthentication: false`.

## 3. Sign a server challenge

```dart
// A single-use random nonce issued by your server.
final Uint8List challenge = await fetchChallengeFromServer();

final signed = await biometric.createSignatureFromBytes(
  payload: challenge,
  keyAlias: 'login',
  promptMessage: 'Sign in',
  config: CreateSignatureConfig(
    promptSubtitle: 'example.com', // Android prompt customisation
    allowDeviceCredentials: false,
  ),
);

if (signed.code == BiometricError.success) {
  await sendToServer(signature: signed.signature!); // base64 by default
  // signed.authenticationType: biometric / credential / unknown. It is a
  // client claim — reported on Android, inferred on Apple, always unknown
  // on Windows.
}
```

## 4. Verify on the server

The server — never the app — decides whether a signature is valid:

- Verify with the public key it stored at registration: **ECDSA P-256 with SHA-256** (DER
  signature) for EC keys, **RSA PKCS#1 v1.5 with SHA-256** for RSA keys. Accept high-S ECDSA
  signatures; no platform normalises them.
- Verify over exactly the bytes it issued, and consume the nonce so it cannot be replayed.

The plugin README has Node.js, Python and Go verification snippets.

## 5. Decrypt data encrypted by the server

```dart
final result = await biometric.decrypt(
  payload: ciphertextBase64,
  payloadFormat: PayloadFormat.base64, // raw is also base64-decoded
  keyAlias: 'vault',
  promptMessage: 'Reveal secret',
);
if (result.code == BiometricError.success) {
  final text = result.decryptedData!; // always UTF-8 text
}
```

The server must encrypt with the scheme of the platform and key it registered:

| Key | Encrypt to | Scheme |
|-----|------------|--------|
| Android `ecdsa` + `enableDecryption: true` (hybrid mode) | `decryptingPublicKey` | ECIES P-256, X9.63-KDF-SHA256 (empty shared info) → AES-128-GCM key + 12-byte IV |
| Android `rsa` + `enableDecryption: true` | `publicKey` | RSA-OAEP, SHA-256, **MGF1-SHA-1** |
| iOS/macOS `ecdsa` | `publicKey` | Apple ECIES (`eciesEncryptionStandardX963SHA256AESGCM`) |
| iOS/macOS `rsa` | `publicKey` | RSA-OAEP, SHA-256, **MGF1-SHA-256** |
| Windows | — | not supported (`notAvailable`) |

RSA-2048 fits at most 190 bytes of plaintext; encrypt a random AES key instead of large data,
and base64-encode binary data because `decrypt` returns a string.

## 6. Hardware key attestation (Android)

```dart
final Uint8List serverChallenge = await fetchAttestationChallenge(); // 1–128 bytes

final attested = await biometric.createKeys(
  keyAlias: 'login',
  config: CreateKeysConfig(
    signatureType: SignatureType.ecdsa,
    attestationChallenge: serverChallenge,
  ),
);

switch (attested.code) {
  case BiometricError.success:
    // DER certificates, leaf first. The server verifies the chain up to
    // Google's roots, the challenge, the security level (TEE/StrongBox),
    // that the attested key equals attested.publicKey, and revocation.
    await sendChainToServer(attested.attestationCertificateChain!);
  case BiometricError.notSupported:
    // iOS, macOS, Windows, Android 6, or a keystore that cannot attest.
    break;
  case BiometricError.notAvailable:
    // Transient: retry later with a fresh challenge.
    break;
  default:
    break;
}
```

`getKeyInfo(keyAlias: 'login').attestationCertificateChain` returns the chain again later (for
example to retry an upload).

## 7. Handle errors by code

```dart
final signed = await biometric.createSignature(
  payload: 'hello',
  keyAlias: 'login',
  promptMessage: 'Confirm',
);

switch (signed.code) {
  case BiometricError.success:
    break;
  case BiometricError.userCanceled:
  case BiometricError.systemCanceled:
    // Do nothing; let the user try again.
    break;
  case BiometricError.keyInvalidated:
  case BiometricError.keyNotFound:
    // Biometric enrollment changed, or the key is gone (reinstall, restore):
    // delete it, create a new one and register the new public key.
    await biometric.deleteKeys(keyAlias: 'login');
  case BiometricError.lockedOut:
  case BiometricError.lockedOutPermanent:
    // Offer the device credential, e.g. simplePrompt with
    // SimplePromptConfig(allowDeviceCredentials: true).
    break;
  case BiometricError.notEnrolled:
  case BiometricError.passcodeNotSet:
    // Send the user to system settings.
    break;
  default:
    // signed.error has details.
    break;
}
```

`getKeyInfo(keyAlias: ..., checkValidity: true)` reports missing (`exists: false`) and
invalidated (`isValid: false`) keys without a prompt — call it on launch.

## Scenario apps

Each runs a mock server in-process so you can watch (and tamper with) what a backend checks.
They live in the GitHub repository, not in this package:

- [Passwordless Login](https://github.com/chamodanethra/biometric_signature/tree/main/passwordless_login) —
  per-account keys, server-verified Android attestation, replay-resistant challenge-response
  sign-in.
- [Step-up Banking](https://github.com/chamodanethra/biometric_signature/tree/main/banking_app) —
  a silent device key for request signing and a biometric key for approving transfers.
- [Secure Vault](https://github.com/chamodanethra/biometric_signature/tree/main/secure_vault) —
  secrets sealed with ECIES or RSA-OAEP and revealed by biometric decryption.

See [EXAMPLES.md](https://github.com/chamodanethra/biometric_signature/blob/main/EXAMPLES.md)
for walkthroughs.
