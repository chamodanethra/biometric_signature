# Example apps

A biometric prompt that returns `true` only protects your app's UI: anything that can hook or
patch the app can fake that `true`. `biometric_signature` instead gives you a key pair in secure
hardware whose private key only works after the user authenticates, so your **server** can check
a signature instead of trusting the app. The four example apps show what that makes possible,
and what the server has to check for it to hold.

| App | Story | What it shows | Platforms |
|-----|-------|---------------|-----------|
| [`example/`](example/) — API Explorer | Every method, option, format and error code, one screen per area | All of the plugin's API; local signature verification; attestation-chain inspection; a call log with "Copy as Dart" | Android, iOS, macOS, Windows |
| [`passwordless_login/`](passwordless_login/) | Sign in without a password: each account gets its own device-bound key | Android key attestation verified by the server, per-account aliases, single-use challenge-response with `createSignatureFromBytes`, re-binding after `keyInvalidated` | Android (attested); iOS, macOS, Windows with attestation turned off |
| [`banking_app/`](banking_app/) | Step-up transaction signing | A silent key (`requireAuthentication: false`) signs every API request; a biometric key approves transfers by signing the exact bytes the bank issued; risk tiers, where the largest transfers need a key *attested* as biometric-only | Android (all tiers); iOS, macOS, Windows capped below the top tier |
| [`secure_vault/`](secure_vault/) | Secrets only the enrolled user can reveal | `decrypt` with the right scheme per platform (Android hybrid ECIES, Android RSA-OAEP, Apple Secure Enclave ECIES, Apple RSA-OAEP), envelopes for large items, sharing between devices, what an enrollment change does to sealed data | Android, iOS, macOS (Windows can't decrypt) |

## Running them

Each directory is a normal Flutter app that depends on the plugin by path:

```bash
cd passwordless_login   # or example, banking_app, secure_vault
flutter run
```

- Android: the apps already use `FlutterFragmentActivity` and the `USE_BIOMETRIC` permission.
  Key attestation needs a physical device; an emulator's software attestation is rejected, as
  a real server would reject it.
- iOS/macOS: Face ID / Touch ID need a device, or the Simulator's *Features → Face ID*
  menu (which can also change the enrollment, to trigger `keyInvalidated`).
- Windows: needs Windows Hello with a PIN.
- `flutter test` in each app runs its flows against a software fake of the plugin
  (`SoftwareBiometricPlatform`), so they run anywhere.

## The mock server

The three scenario apps run their "server" in the same process, behind a mock network
(`MockTransport`) that round-trips every request through JSON, the way a real HTTP API would.
Each app has a **server console** (the terminal icon) with the server's records, an audit log,
every request and response, the server's policy, and **faults** you can inject: tampered
fields, replayed requests, expired challenges, failed uploads. They show what each server check
catches.

The shared code lives in [`example/packages/examples_shared`](example/packages/examples_shared):

- `crypto.dart` — signature verification (RSA PKCS#1 v1.5 and ECDSA P-256 over SHA-256),
  RSA-OAEP with the per-platform MGF1 digest, both ECIES variants, and which one a key needs.
- `attestation.dart` — X.509 and Android key-description parsing, and chain verification up to
  Google's attestation roots.
- `server.dart` — the mock transport, single-use challenges, a replay cache, storage and an
  audit log.
- `ui.dart` / `testing.dart` — guidance for every `BiometricError`, shared widgets, and the
  software fake of the plugin.

This is demo code. It is written to be read, not deployed. A real server also needs TLS, rate
limiting, durable storage and, for attestation, a check of Google's revocation list
(`https://android.googleapis.com/attestation/status`), which the demos deliberately skip and
flag in every report. Google recommends its
[key attestation library](https://github.com/android/keyattestation) over custom verifiers.

## `example/` — API Explorer

One screen per area: Device, Keys, Sign, Decrypt, Inventory, Prompt and Errors. Everything
goes through a call log you can copy as Dart.

Try this:

1. **Keys**: create an EC key under `explorer_a`, then create it again with *failIfExists* to
   get `keyAlreadyExists`. On Android, add a 32-byte attestation challenge and open the
   attestation report; a 129-byte challenge gives `invalidInput`.
2. **Sign**: sign a random nonce with `createSignatureFromBytes`, then *Verify locally*. The
   same check rejects a message with one flipped bit.
3. **Decrypt**: the Explorer picks the encryption scheme from the key it finds, encrypts
   locally, and asks the plugin to decrypt. Switch between base64, hex and raw payloads.
4. **Errors**: trigger `keyNotFound`, `notSupported` and `invalidInput`, and follow the steps
   for `keyInvalidated`.

## `passwordless_login/` — attested device binding

Registering an account creates a key under its own alias (`acct_<id>`, with `failIfExists`).
On Android the server first issues an attestation challenge and verifies the returned chain:
Google's root, the challenge, a TEE or StrongBox security level, and that the attested key is
the one being registered. Signing in signs a single-use server nonce with
`createSignatureFromBytes`; the server rebuilds the signed bytes itself instead of trusting the
app's copy.

Try this:

1. Register, and read the attestation report (on a physical Android device).
2. Sign in and follow the signing trace, then use the console to tamper with a signature,
   replay a sign-in, expire a nonce, or present it as another user.
3. Fail the registration upload from the console, then *Retry upload*: the app re-reads the
   chain with `getKeyInfo`.
4. Enroll a new fingerprint or face in system settings and sign in again: `keyInvalidated`,
   then re-bind with the recovery code.

This sign-in is replay-resistant, but it is **not** phishing-resistant: the app chooses the
relying-party string it signs, and the OS doesn't bind it to a web origin. Use platform
passkeys if you need that. [More](passwordless_login/README.md)

## `banking_app/` — step-up transaction signing

The device has two keys:

| Alias | Config | What a signature proves |
|-------|--------|-------------------------|
| `device_binding` | `requireAuthentication: false`, attested on Android | This device signed the request. Nothing about who was holding it. |
| `txn_approval` | `enforceBiometric`, `setInvalidatedByBiometricEnrollment: true`, attested on Android | The enrolled user approved these exact bytes (biometric-only when attested as such). |

The bank decides what each transfer needs:

| Tier | Amount | Required |
|------|--------|----------|
| A | up to $100 | A silent `device_binding` signature |
| B | up to $2,000 | A `txn_approval` signature |
| C | over $2,000 | A `txn_approval` signature from a key that Android attestation proves is biometric-only |

The prompt shows the amount and payee. The bank verifies the signature over the bytes it
issued, and treats `authenticationType` as a client claim to record, not as evidence. After an
enrollment change, the silent key still works, so the user can re-verify and get a new
approval key.

Try this: make tier A, B and C transfers; tamper with the amount or replay a confirmation from
the console; enroll a new fingerprint and re-verify. [More](banking_app/README.md)

## `secure_vault/` — biometric decryption

A provisioning server seals secrets to the device's vault key using the scheme that key
decrypts. The device stores only ciphertext; each item is revealed by `decrypt`, which only
succeeds after the user authenticates.

| Platform and key | Scheme the server encrypts with |
|------------------|---------------------------------|
| Android `ecdsa` + `enableDecryption` | ECIES P-256, X9.63-KDF-SHA256 with empty shared info, AES-128-GCM with a derived 12-byte IV, against `decryptingPublicKey` |
| Android `rsa` + `enableDecryption` | RSA-OAEP, SHA-256, MGF1-SHA-1 |
| iOS/macOS `ecdsa` | Apple `eciesEncryptionStandardX963SHA256AESGCM` |
| iOS/macOS `rsa` | RSA-OAEP, SHA-256, MGF1-SHA-256 |
| Windows | Not supported (`decrypt` returns `notAvailable`) |

Try this: reveal a server secret in base64 and in hex; add a note (sealing needs no prompt,
revealing does); compare `simplePrompt` (a UI gate) with `decrypt` (a cryptographic gate);
share an item with another vault address; enroll a new fingerprint and see which items survive
re-provisioning. [More](secure_vault/README.md)

## What the demos claim, and what they don't

- A signature proves possession of a hardware-backed key whose access policy was satisfied
  (biometric, optionally the device PIN). It does not identify a person, so it is not
  evidence of non-repudiation.
- Only Android attests individual keys. On iOS, macOS and Windows the server takes the
  platform's word that a key is hardware-backed; the demos show that as "not attested".
- A silent key (`requireAuthentication: false`) proves the device, not the user.
- `authenticationType` is reported by the app and isn't signed. Base policy on what the key
  itself requires, which on Android the attestation proves.
- None of the demos is FIDO, WebAuthn or a passkey implementation.

## Where each API is used

| API or option | Explorer | Passwordless | Banking | Vault |
|---------------|:-:|:-:|:-:|:-:|
| `createKeys` with `keyAlias`, `failIfExists` | ✓ | ✓ | ✓ | ✓ |
| `attestationChallenge` / `attestationCertificateChain` | ✓ | ✓ | ✓ | |
| `requireAuthentication: false` | ✓ | | ✓ | |
| `enableDecryption`, hybrid mode | ✓ | | | ✓ |
| `createSignature` (text) | ✓ | | ✓ | |
| `createSignatureFromBytes` | ✓ | ✓ | ✓ | |
| `decrypt` with `PayloadFormat` base64 / hex | ✓ | | | ✓ |
| `getKeyInfo(checkValidity: true)` | ✓ | ✓ | ✓ | ✓ |
| `getKeyInfo(keyFormat: KeyFormat.pem)` | ✓ | | | ✓ |
| `biometricKeyExists` | ✓ | | | ✓ |
| `deleteKeys` / `deleteAllKeys` | ✓ | ✓ | ✓ | ✓ |
| `simplePrompt` | ✓ | ✓ | | ✓ |
| `biometricAuthAvailable`, `isDeviceLockSet` | ✓ | ✓ | ✓ | ✓ |
| Prompt texts (`promptSubtitle`, `promptDescription`, `cancelButtonText`) | ✓ | ✓ | ✓ | ✓ |
| `keyInvalidated` / `keyNotFound` recovery | ✓ | ✓ | ✓ | ✓ |
| `authenticationType` | ✓ | ✓ | ✓ | ✓ |

The Explorer also covers every `KeyFormat`, `SignatureFormat` and `PayloadFormat`, and every
`BiometricError`.
