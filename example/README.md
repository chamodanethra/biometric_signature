# Biometric Signature Explorer

The API Explorer for [`biometric_signature`](https://pub.dev/packages/biometric_signature).
Every method, every config field, every output format and every error code is reachable from
its screens, and every call is recorded with its arguments, its full result and a runnable
"Copy as Dart" snippet.

For end-to-end stories with a mock server (registration, login, transaction signing, sealed
secrets), see the [scenario apps](#scenario-apps).

## Screens

| Screen | Plugin API | What to look at |
|--------|------------|-----------------|
| **Device** | `biometricAuthAvailable`, `isDeviceLockSet` | Every availability field, what `isDeviceLockSet` means on each platform, and a capability matrix (EC keys, decryption, attestation, silent keys, invalidation, `authenticationType`). |
| **Keys** | `createKeys` | Alias, `signatureType`, all four `KeyFormat`s (including how `publicKeyBytes` differs per platform) and every `CreateKeysConfig` field: `requireAuthentication`, `enforceBiometric`, `useDeviceCredentials`, `setInvalidatedByBiometricEnrollment`, `enableDecryption`, `failIfExists`, the prompt texts and `attestationChallenge` (none / 32 / 128 / 129 bytes — 129 shows `invalidInput`). On Android an attestation chain is inspected locally and can be copied as PEM. |
| **Sign** | `createSignature`, `createSignatureFromBytes` | Text or byte payloads (random 32-byte nonce or hex), every `SignatureFormat` and `KeyFormat`, `CreateSignatureConfig`, `authenticationType`, and **Verify locally** against the returned key and the key recorded at creation (plus a tampered message that must fail). |
| **Decrypt** | `decrypt` | The encryption scheme is derived from the real key (`getKeyInfo`) and platform — Android hybrid ECIES, Apple ECIES, or RSA-OAEP with the platform's MGF1 digest. Encrypt locally or paste ciphertext, pick `PayloadFormat` (`raw` is base64-decoded natively), set `DecryptConfig`, and check the round trip. |
| **Inventory** | `getKeyInfo`, `biometricKeyExists`, `deleteKeys`, `deleteAllKeys` | The known aliases (`default`, `explorer_a`, `explorer_b`, `explorer_silent`) plus one custom alias — the plugin cannot list aliases. `checkValidity`, key format, attestation chains, and `deleteAllKeys` behind a confirmation. |
| **Prompt** | `simplePrompt` | Every `SimplePromptConfig` field, including `biometricStrength.weak` and device-credential fallback. |
| **Errors** | all 18 `BiometricError` codes | Meaning, recovery, platforms that emit each code and how to trigger it. One-tap triggers for `keyAlreadyExists`, `invalidInput`, `notSupported`, `keyNotFound` and `userCanceled`; walkthroughs for `keyInvalidated` and `lockedOut`. |

The **call log** (app bar icon) lists every plugin call with its duration, arguments, every
non-null result field and error code. "Copy as Dart" copies a self-contained function that
repeats the call.

Controls that a platform ignores are tagged (for example *Android only*). On Windows, EC keys,
decryption and attestation are disabled with an explanation, because Windows Hello keys are
RSA-only and cannot decrypt.

> **Local checks are demos.** Signature verification and attestation inspection run inside the
> app so you can see what a server sees. A real server issues the challenges, stores the public
> key at registration, verifies there, and checks attestation revocation. The app never gets to
> decide whether its own key is trusted.

## Run it

```bash
cd example
flutter pub get
flutter run
```

The Explorer depends on the plugin and on the shared example helpers
(`packages/examples_shared`) by path, so it always runs against the code in this repository.

### Android

- Use a device or emulator with a screen lock and an enrolled fingerprint (or Class 3 face).
  On an emulator: *Settings → Security → Fingerprint*, then *Extended controls → Fingerprint*
  to touch the sensor.
- `MainActivity` extends `FlutterFragmentActivity`, which `BiometricPrompt` requires — your
  app needs the same change. The manifest declares `android.permission.USE_BIOMETRIC`.
- Key attestation needs Android 7+. Emulators attest with a software root, so the local
  inspection reports the chain as untrusted — use a physical device to see a TEE or StrongBox
  result.
- See the plugin README for the `compileSdk` / NDK settings Flutter 3.24.5 needs.

### iOS

- `NSFaceIDUsageDescription` is set in `ios/Runner/Info.plist`; your app needs one too.
- Prefer a physical device: Secure Enclave keys may not be available in the Simulator. In the
  Simulator, enroll Face ID with *Features → Face ID → Enrolled* and answer prompts with
  *Matching Face* / *Non-matching Face*.
- Key attestation is Android-only: any `attestationChallenge` returns `notSupported`.

### macOS

Run on a Mac with Touch ID (or a paired Magic Keyboard with Touch ID). The Secure Enclave is
used the same way as on iOS.

### Windows

Set up Windows Hello with a PIN. Keys are RSA-2048, every use prompts (even
`requireAuthentication: false` keys), `authenticationType` is always `unknown`, and `decrypt`
returns `notAvailable`.

## Tests

```bash
cd example
flutter test
```

The widget tests install `SoftwareBiometricPlatform` — a software fake of the plugin platform
with real cryptography — and drive the Explorer as Android, iOS, macOS and Windows:
create keys, sign and verify, decrypt with each scheme, inspect a synthetic attestation chain,
run error triggers, and copy a call as Dart. `test/version_test.dart` keeps the version shown in
the app in step with the plugin's `pubspec.yaml`.

## Code layout

```
lib/
  main.dart, app.dart          app shell: bottom bar on phones, rail on wide screens
  version.dart                 plugin version shown in the app (checked by a test)
  state/                       ExplorerState, one controller per screen, the call log,
                               TracedApi (the plugin API with every call recorded)
  screens/                     one file per destination
  widgets/                     form controls, result cards, alias picker, call log view
packages/examples_shared/      helpers shared with the scenario apps (crypto, attestation,
                               UI kit, fake platform)
```

## Scenario apps

The repository also has three scenario apps with an in-process mock server. They are not
included in the pub.dev package.

- [Passwordless Login](https://github.com/chamodanethra/biometric_signature/tree/main/passwordless_login) —
  attested device binding and replay-resistant challenge-response sign-in.
- [Step-up Banking](https://github.com/chamodanethra/biometric_signature/tree/main/banking_app) —
  a silent device key signs every request; a biometric key approves transfers.
- [Secure Vault](https://github.com/chamodanethra/biometric_signature/tree/main/secure_vault) —
  secrets sealed to the device key (ECIES or RSA-OAEP) and revealed by biometric decryption.

[EXAMPLES.md](https://github.com/chamodanethra/biometric_signature/blob/main/EXAMPLES.md) walks
through each of them.
