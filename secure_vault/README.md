# Secure Vault

An example app for [`biometric_signature`](../README.md): secrets are sealed to
a hardware-backed key, and the only way to read one is the plugin's `decrypt()`
behind a biometric prompt.

- A **provisioning server** seals secrets (a Wi-Fi password, an API token,
  recovery codes) to the device's vault key. The device stores **ciphertext
  only**.
- **Reveal** calls `decrypt()`. The private key never leaves the TEE, StrongBox
  or Secure Enclave. The plaintext appears for 30 seconds and lives only in
  Dart memory.
- **Add note** seals a note to the vault's own public key with **no prompt**:
  the vault is write-only until you authenticate.
- **Enrolling a new fingerprint or face invalidates the key.** Everything
  sealed to it becomes unreadable for good (crypto-shredding). Re-provisioning
  creates a new key; the server seals its secrets again, but notes that existed
  only on the device are gone. This is deliberate.
- **Share**: export a "vault address" (public data only), seal a secret for
  someone else's vault, and import items sealed to yours. Senders need no key
  and no prompt, so a Windows PC can seal too.

The server is an in-process mock behind a simulated network. Open the server
console (terminal icon) to see its records, audit log and wire log, and to
inject faults. It is demo code, not a production design; see
[What a real server must add](#what-a-real-server-must-add).

## How it works

```text
 Provisioning server (in-process demo)            This device
 ─────────────────────────────────────            ────────────────────────────────────────
                                                   createKeys(keyAlias: 'vault',
                                                     enableDecryption: true, ...)
                                                     → key pair in the TEE / Secure Enclave
 POST /vault/register  ◄─────────────────────────  publicKey, decryptingPublicKey,
   EncryptionTarget.resolve(platform, key)           algorithm, isHybridMode, platform
   → scheme (never from a UI toggle)
 POST /vault/sync      ─────────────────────────►  sealed items → stored as ciphertext
   seals each secret with the scheme                 (title, size, dates stay in the clear)

                                                   Reveal:
                                                     decrypt(payload, payloadFormat) ─ prompt
                                                     └─ plaintext on screen for 30 s,
                                                        hidden on app pause

                                                   Add note:
                                                     seal to the vault's own public key
                                                     (pure Dart, no prompt, no private key)
```

Items up to 190 bytes are sealed directly. Longer ones use an envelope: the
text is encrypted with AES-256-GCM under a random data key, and only that data
key is sealed to the vault key. `decrypt()` returns the data key and the app
opens the content in Dart. 190 bytes is the RSA-2048 OAEP limit; the app uses
the same rule for every scheme.

## Encryption scheme per platform

The scheme depends on the platform **and** the key. The server records it at
registration (`EncryptionTarget.resolve` in `examples_shared`).

| Platform | Setup choice | Key(s) created | Seal to | Scheme |
|---|---|---|---|---|
| Android | **EC** (default) | Hybrid mode (`isHybridMode: true`): a hardware EC P-256 signing key, plus a software EC P-256 decryption key wrapped by a biometric-bound keystore AES key | `decryptingPublicKey` | ECIES, Android variant |
| Android | **RSA-OAEP** | Hardware RSA-2048 keystore key with the decrypt purpose | `publicKey` | RSA-OAEP, SHA-256, MGF1-SHA-1 |
| iOS, macOS | **EC** (default) | One Secure Enclave P-256 key that signs and decrypts | `publicKey` | ECIES, Apple variant (`eciesEncryptionStandardX963SHA256AESGCM`) |
| iOS, macOS | **RSA-OAEP** | An RSA-2048 key, stored wrapped by a Secure Enclave key; it signs and decrypts (`isHybridMode: false`) | `publicKey` | RSA-OAEP, SHA-256, MGF1-SHA-256 |
| Windows | — | Windows Hello RSA key | — | None: `decrypt()` returns `notAvailable` |

`enableDecryption: true` matters only on Android. iOS and macOS keys always
decrypt and ignore it.

Prompts at setup: Android hybrid EC shows one prompt during `createKeys`, to
wrap the decryption key. Android RSA and Apple keys are created without a
prompt. Every reveal prompts.

On Windows, setup shows a banner instead of a create button, because there is
nothing to reveal. You can still use **Seal a secret for another vault**.

## Plugin APIs and options used

| API / option | Where | Why |
|---|---|---|
| `biometricAuthAvailable()`, `isDeviceLockSet()` | Setup preflight | Shows `passcodeNotSet` / `notEnrolled` guidance before key creation |
| `createKeys(keyAlias: 'vault', ...)` with `CreateKeysConfig(signatureType: ecdsa \| rsa, enableDecryption: true, setInvalidatedByBiometricEnrollment: true, useDeviceCredentials, failIfExists: true, promptSubtitle, promptDescription, cancelButtonText)` | Setup, re-provision | The vault key. `failIfExists` never silently overwrites a key that survived a reinstall |
| `KeyCreationResult.publicKey`, `decryptingPublicKey`, `algorithm`, `keySize`, `isHybridMode` | Registration | The server resolves the scheme from these |
| `getKeyInfo(keyAlias: 'vault', checkValidity: true)` (via `probeKey`) | Launch, key status, after an unexpected `decrypt` failure, "register the existing key" | Tells an invalidated or missing key from a damaged ciphertext |
| `getKeyInfo(keyFormat: KeyFormat.pem)` | Share → My address | The address carries the PEM public key |
| `biometricKeyExists(checkValidity: true)` | Key status | |
| `decrypt(payload, payloadFormat: base64 \| hex, keyAlias: 'vault', promptMessage, config: DecryptConfig(promptSubtitle, promptDescription, cancelButtonText, allowDeviceCredentials))` | Reveal | The cryptographic gate. The item ciphertext has a base64 / hex toggle |
| `DecryptResult.authenticationType` | Reveal | Biometric or PIN / passcode. Reported by Android, inferred on Apple |
| `simplePrompt(promptMessage, config: SimplePromptConfig(...))` | "Hide titles until unlocked" | A UI gate, shown next to Reveal for contrast |
| `deleteKeys(keyAlias: 'vault')` | Re-provision, replace an existing key | |
| `deleteAllKeys()` | Server console → Reset demo | |

Error codes handled: `keyInvalidated` (crypto-shredding), `keyNotFound` (key
lost), `keyAlreadyExists` (register or replace), `passcodeNotSet`,
`notEnrolled`, `notAvailable` (Windows), `userCanceled` and `unknown` (with a
key health check). Every other code gets the shared `guidanceFor` message.

Prompt texts: `promptSubtitle`, `promptDescription`, `cancelButtonText` and
`allowDeviceCredentials` apply on Android only. iOS and macOS show only
`promptMessage`, for example `Reveal "Office Wi-Fi password"`. When titles are
hidden, the prompt says `Reveal a vault item` instead, so the title does not
appear in the system dialog.

## Run it

```sh
cd secure_vault
flutter run            # Android, iOS or macOS; Windows shows the explanation
```

Use a physical device for the full story. The iOS Simulator has no Secure
Enclave, so key creation may fail there. An Android emulator with an enrolled
fingerprint works, with a software-backed keystore.

## Try this

1. **Create vault key** with EC. Note the scheme on the vault card: *ECIES
   (Android hybrid)* or *ECIES (Apple Secure Enclave)*.
2. Open **Office Wi-Fi password** and tap **Reveal**. Authenticate; the secret
   shows for 30 seconds with the authentication type. Switch the ciphertext to
   **hex** and reveal again (`payloadFormat: hex`). Send the app to the
   background: the secret hides.
3. Open **Account recovery codes**. It is an envelope: `decrypt()` only sees the
   wrapped data key.
4. **Add note**. Saving does not prompt. Revealing the note does.
5. Turn on **Hide titles until unlocked** and tap **Show titles**. That is
   `simplePrompt`: a UI gate. The titles were in plain text all along.
6. Server console → **Faults** → *Tamper with the next delivery: the ciphertext
   the device decrypts*. Tap **Sync** and reveal the Wi-Fi password. The
   decryption fails, the app checks the key, finds it healthy and blames the
   ciphertext. **Sync a fresh copy** repairs it. The *envelope content* fault
   shows the second layer: you authenticate, then the AES-GCM tag rejects the
   content.
7. **Share** → *My address* → copy. *Seal for someone* → paste your own
   address → **Check address** → **Seal** → copy. *Import* → paste → reveal it.
8. Enroll an extra fingerprint or face in system settings, come back and reveal
   an item. You get `keyInvalidated` and the crypto-shredding banner.
   **Re-provision**: the server secrets return, sealed to the new key; your note
   and the imported item are *Unrecoverable*. Delete them.
9. Server console → *Reset demo*, then *Fail the next registration*, then
   **Create vault key**. The key now exists on the device but the server never
   heard of it; **Retry registration** re-reads it with `getKeyInfo`, with no
   new key and no prompt.
10. **Reset demo** when done (`deleteAllKeys()` and both stores cleared).

## What this does and does not protect

- **The device stores only ciphertext.** Titles, sizes, origins and dates are
  stored in the clear (SharedPreferences under `client.`).
- **Plaintext exists only after a successful `decrypt()`**, and then in Dart
  memory until the UI drops it and the garbage collector reclaims it. Dart
  strings cannot be wiped. The app never writes plaintext to storage, does not
  make it selectable (so it does not end up on the clipboard), and hides it
  after 30 seconds or when the app leaves the foreground.
- **Envelopes put the data key in Dart memory** for a moment, the same way.
- **Notes are write-only without authentication.** Anyone who can run the app
  can add a note; nobody can read one without the key and the prompt.
- **A new fingerprint or face permanently locks device-only items**, with
  `setInvalidatedByBiometricEnrollment: true`. An attacker who enrolls their own
  biometrics cannot read the vault; neither can you. Server-provisioned items
  can be sealed again, device-only notes cannot. On iOS and macOS, a key created
  with `useDeviceCredentials: true` is *not* invalidated by enrollment changes,
  because the passcode can always unlock it.
- **`simplePrompt` is a UI gate.** It proves nothing to a server and protects no
  data.
- **`authenticationType` is a client claim.** Android reports it; Apple
  platforms infer it; nothing signs it.
- **Shared items are not authenticated.** Anyone with your address can seal to
  it, and the "from" field is just text. To authenticate the sender, have them
  sign the item as well (for example with `createSignature` and a key you have
  registered).

## What a real server must add

- **Authenticated key registration.** Here anyone can register any key for any
  device id. Bind the vault key to an authenticated account and device: for
  example, sign the registration with a key registered through attested device
  binding (see [`passwordless_login`](../passwordless_login/)). The app's check
  that the server echoes the same key fingerprint catches accidents, not an
  attacker who controls the connection.
- **Android key attestation.** Pass an `attestationChallenge` and verify the
  chain before sealing anything. In hybrid EC mode only the hardware *signing*
  key is attested; the software decryption key cannot be. In RSA mode the
  attested RSA key is the one that decrypts. Apple platforms have no per-key
  attestation.
- **TLS**, rate limits and access control on every endpoint.
- **Secret storage in a KMS or HSM**, with an audit trail of every seal. This
  demo keeps the plaintext in SharedPreferences under `server.`.
- **Key rotation and revocation.** Re-seal on a new key (as the demo does) and
  retire the old registration.
- **Persistence and backups** that never assume device keys can be restored:
  keystore and Secure Enclave keys never leave the device.

## Encryption parameters

This is for a backend that seals to a device. The Dart reference is in
`example/packages/examples_shared/lib/src/crypto/`: `EncryptionTarget.resolve`,
`eciesEncrypt`, `rsaOaepEncrypt` and `sealEnvelope`.

`decrypt()` returns the plaintext as **UTF-8 text**, so only encrypt UTF-8.
Base64 binary data (such as a data key) first. Send the ciphertext as base64
(`payloadFormat: base64`) or hex (`payloadFormat: hex`). Every `publicKey`
string the plugin returns is SubjectPublicKeyInfo DER, in base64, PEM or hex.

**ECIES wire format (both variants):** `ephemeral public key (65 bytes, 04‖X‖Y)
‖ AES-GCM ciphertext ‖ 16-byte tag`. Z is the x-coordinate of
ECDH(ephemeral private key, recipient public key) on P-256. There is no AAD.

| Scheme | Recipient key | Key derivation | Cipher |
|---|---|---|---|
| ECIES, Android hybrid | `decryptingPublicKey` | ANSI X9.63 KDF, SHA-256, shared info **empty**, 28 bytes: bytes 0–15 = AES key, bytes 16–27 = 12-byte IV | AES-128-GCM, 128-bit tag |
| ECIES, Apple (`eciesEncryptionStandardX963SHA256AESGCM`) | `publicKey` | ANSI X9.63 KDF, SHA-256, shared info = **the 65-byte ephemeral public key**, 16 bytes = AES key | AES-128-GCM, **16 zero bytes** as IV, 128-bit tag |
| RSA-OAEP, Android keystore | `publicKey` | — | RSA-2048 OAEP, SHA-256 digest, **MGF1 with SHA-1**, empty label, ≤ 190 bytes |
| RSA-OAEP, Apple (`rsaEncryptionOAEPSHA256`) | `publicKey` | — | RSA-2048 OAEP, SHA-256 digest, **MGF1 with SHA-256**, empty label, ≤ 190 bytes |

A payload for one variant does not decrypt on the other platform.

RSA-OAEP with common tools:

```python
# Python `cryptography`
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

android = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None)
apple = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
ciphertext = public_key.encrypt(plaintext_utf8, android)
```

```sh
# OpenSSL, Android keystore key (use rsa_mgf1_md:sha256 for Apple)
openssl pkeyutl -encrypt -pubin -inkey vault.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha1 -in secret.txt | base64
```

**This app's envelope** (an app format, not a plugin format):

```json
{
  "v": 1,
  "alg": "A256GCM",
  "scheme": "ECIES (Android hybrid)",
  "wrappedKey": "<base64: the device scheme's ciphertext of base64(dataKey)>",
  "iv": "<base64: 12 random bytes>",
  "ciphertext": "<base64: AES-256-GCM(dataKey, iv, content) ‖ 16-byte tag, no AAD>"
}
```

`dataKey` is 32 random bytes. The device passes `wrappedKey` to `decrypt()`,
base64-decodes the returned text and opens `ciphertext` with it.

**Vault address** (Share → My address):

```json
{
  "type": "secure-vault/address",
  "v": 1,
  "platform": "ios",
  "isHybridMode": false,
  "scheme": { "type": "ecies", "variant": "apple", "publicKeySpki": "<base64>" },
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n…",
  "fingerprint": "<sha256 of the SPKI, hex>"
}
```

A sender re-derives the scheme from `platform`, `isHybridMode` and
`publicKeyPem`, and rejects the address if `scheme` disagrees.

## Code map

| Path | What |
|---|---|
| `lib/server/provisioning_server.dart` | `/vault/register` (resolves the scheme) and `/vault/sync` (seals the secrets); audit log |
| `lib/server/in_transit_tamper.dart` | Simulated attacker that flips a bit in a delivered item |
| `lib/client/vault_key_manager.dart` | Preflight, `createKeys`, `getKeyInfo`, `probeKey`, `deleteKeys` for alias `vault` |
| `lib/client/reveal_service.dart` | `decrypt()` + envelope opening; classifies failures |
| `lib/client/sharing.dart` | Vault address, seal for a recipient, import |
| `lib/client/vault_repository.dart` | Device storage (`client.` prefix) |
| `lib/client/vault_controller.dart` | Use cases: provision, reconcile, reveal, re-provision, reset |
| `lib/models/` | `SealedItem` (the stored and shared item format), `VaultKeyRecord` |
| `lib/screens/` | setup, vault, item, add note, share, key status, server console |

## Tests

```sh
flutter test
```

The tests run against `SoftwareBiometricPlatform`, a software fake of the
plugin with real cryptography. They cover:

- each scheme: Android hybrid ECIES, Android RSA-OAEP (MGF1-SHA-1), Apple ECIES
  and Apple RSA-OAEP (MGF1-SHA-256), through the real `decrypt()` API with base64
  and hex payloads;
- envelopes and prompt-free notes;
- Windows (`notAvailable`);
- invalidation → `keyInvalidated` → re-provisioning, with server secrets
  restored and device notes lost;
- a missing key (`keyNotFound`) and a key that survived a reinstall
  (`keyAlreadyExists`);
- sharing between simulated Android and Apple devices, and inconsistent
  addresses;
- tampering in transit, and failed registration or sync;
- widget flows (setup → reveal → auto-hide, hide on background) and every
  screen at phone and desktop widths.
