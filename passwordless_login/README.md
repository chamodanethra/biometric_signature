# Passwordless Login — attested device binding

This example signs users in without a password. Each account gets its own hardware key on the device.

- **Registration.** The server issues an attestation challenge. The device creates a key with that challenge. On Android, the server then verifies the key-attestation certificate chain up to Google's roots and assigns a **trust tier**.
- **Sign-in.** The key signs a single-use server nonce. The server checks that signature against the public key it stored at registration.

> **Demo code, not production code.** The "server" is a mock that runs inside the app, behind an in-process JSON transport. It keeps its records in SharedPreferences. It does not check attestation revocation, and it has no TLS and no rate limits. See [What a real server must add](#what-a-real-server-must-add).

## What this is, and what it is not

- **Replay-resistant challenge-response.** Every nonce is random, single use, and expires after 2 minutes. Each one is bound to one user and one purpose (`login` or `unbind`). The server consumes the nonce *before* it checks anything else. It then verifies the signature over bytes it **rebuilds from its own stored challenge**, and never re-serializes the JSON the client sent. So a captured request cannot be replayed, redirected to another user, or reused for another action.
- **Not phishing-resistant.** The signed payload contains an `rp` string, but the app chooses that string and the OS never checks it against a web origin. A look-alike app that relays the server's nonce could get the user to sign it. This is **not** FIDO, WebAuthn or passkeys.
- **Possession, plus a local unlock.** A signature shows that the device holds the key and that the key's access policy was satisfied (biometric, and optionally the device PIN). It does not identify a person, so it gives no non-repudiation.
- **`authenticationType` is a client claim.** The server records it for audit. It is not covered by the signature, so trust is never based on it. On Android, the **attestation** is the verifiable statement of the key's policy: `userAuthType` 2 means biometric only.

## The flow

```mermaid
sequenceDiagram
    participant App
    participant Plugin as biometric_signature
    participant Server as Mock server
    App->>Server: /register/begin {username, platform}
    Server-->>App: challenge (32 B, TTL 5 min, bound to username)
    App->>Plugin: createKeys(acct_<id>, ecdsa, failIfExists, enforceBiometric,<br/>attestationChallenge: challenge)
    Plugin-->>App: publicKey (SPKI) + attestationCertificateChain
    App->>Server: /register/finish {publicKey, chain, …}
    Note over Server: chain → Google root, challenge, key match,<br/>package, security level → trust tier.<br/>Challenge consumed only on success.
    Server-->>App: userId, deviceKeyId, report, one-time recovery code

    App->>Server: /login/begin {username}
    Server-->>App: nonce (single use, TTL 2 min, bound to userId) + key aliases
    App->>Plugin: createSignatureFromBytes(canonical JSON {challengeId, nonce, purpose, rp, userId})
    Plugin-->>App: signature (ECDSA P-256 / SHA-256; RSA PKCS#1 v1.5 on Windows)
    App->>Server: /login/finish {userId, deviceKeyId, challengeId, signature}
    Note over Server: consume nonce first → rebuild payload<br/>from its own record → verify signature
    Server-->>App: session
```

Two further flows use the same building blocks:

- **Recovery (re-bind).** `/recovery/begin` and `/recovery/finish` take the one-time recovery code. The server verifies a fresh attestation for a replacement key, marks the old key `superseded`, and issues a new code.
- **Removal.** `/devices/unbind/begin` and `/devices/unbind/finish` accept a signed request with purpose `unbind`, after which the key stops working.

## Plugin APIs and flags used

| API | Where | Why |
|---|---|---|
| `biometricAuthAvailable()`, `isDeviceLockSet()` | `client/preflight.dart`, Device check screen | Send the user to Settings *before* creating a key. The screens map `passcodeNotSet`, `notEnrolled` and `notAvailable` to guidance. |
| `createKeys` | `client/auth_client.dart` `_createKey` | `keyAlias: acct_<random>` gives one key per account. It also passes `signatureType: ecdsa`, `failIfExists: true`, `enforceBiometric: true`, the user's `useDeviceCredentials` (default off) and `setInvalidatedByBiometricEnrollment` (default on), `promptSubtitle` / `promptDescription` / `cancelButtonText`, and `attestationChallenge` on Android only. |
| `KeyCreationResult.attestationCertificateChain` | registration upload | DER certificates, leaf first, verified by `AttestationVerifier` from `examples_shared`. |
| `getKeyInfo(keyAlias)` | retry upload | Reads the public key **and the same attestation chain** back after a failed upload, with no second prompt. |
| `getKeyInfo(checkValidity: true)` (via `probeKey`) | `client/reconcile.dart`, after sign-in failures | Detects missing and invalidated keys on launch and after errors. |
| `createSignatureFromBytes` + `CreateSignatureConfig` | sign-in, signed unbind | Signs the exact canonical-JSON bytes. The prompt texts are set, and `allowDeviceCredentials` is set per account. |
| `simplePrompt(allowDeviceCredentials: true)` | after `lockedOutPermanent` | Unlocks biometrics with the device PIN, then retries sign-in. |
| `deleteKeys(keyAlias)` | server rejection, removal, re-bind | Deletes one account's key without touching the others. |
| `deleteAllKeys()` | Wipe device keys, Reset demo | Deletes every key on the device. The server's records remain, and the console shows them as orphaned. |

**Error codes and what the app does**

| Code | Outcome |
|---|---|
| `keyAlreadyExists` | A key is still stored under the alias, for example an invalidated key during re-bind, and `failIfExists` kept it. The app asks before running "Delete the old key and continue". |
| `notSupported` (with a challenge) | This keystore cannot attest. If the policy allows unattested keys, the app retries without the challenge. Otherwise it explains that the server will reject the device. |
| `notAvailable` | Retry later, with a fresh challenge. |
| `passcodeNotSet`, `notEnrolled` | The app links to the Device check screen. |
| `keyInvalidated`, `keyNotFound`, or any unexpected error | The app runs `probeKey`. If the key is gone or invalid, the result is **NeedsRebind**, which offers the recovery code, or a new account instead. |
| `lockedOutPermanent` | The user unlocks with the device PIN through `simplePrompt`, then the sign-in retries. |
| `lockedOut`, `userCanceled`, `systemCanceled`, `authenticationFailed`, `notInteractive`, `promptError` | Try again. |

Errors always arrive in `result.code`; the plugin never throws them. The client maps every code and every server rejection to one of five outcomes: `Success`, `NeedsRebind`, `Retryable`, `Blocked` or `Rejected`, defined in `client/outcome.dart`.

## Platform differences

| | Android | iOS / macOS | Windows |
|---|---|---|---|
| Key | EC P-256 in TEE / StrongBox | EC P-256 in the Secure Enclave | RSA-2048 (Windows Hello). `signatureType` is ignored. |
| Attestation | Yes, with trust tier StrongBox or TEE | No. `attestationChallenge` → `notSupported` | No |
| With "Require attestation" on (the default) | Registers | Rejected by the server, with an explanation | Rejected by the server |
| With it off | A chain that fails verification registers as **Untrusted** | Registers as **Not attested** | Registers as **Not attested**; the server verifies RSA PKCS#1 v1.5 |
| Enrollment change | `keyInvalidated` | `keyInvalidated`, except for keys that also accept the passcode | Keys are never invalidated |
| `authenticationType` | Reported by the OS | Inferred by the plugin | Always `unknown` |

Keys and app data can drift apart, and `client/reconcile.dart` handles both directions:

- **Android Auto Backup** restores preferences onto a new phone, but never keystore keys. The account then shows **Key missing** and offers a re-bind.
- **iOS keychain keys survive an uninstall**, but preferences do not. Use **Sign in to an existing account**. The server lists the account's key aliases, like WebAuthn's `allowCredentials`. If one of them is still on the device, signing with it restores the account without a recovery code.

## Layout

```
lib/
  main.dart, app.dart, app_scope.dart   wiring (ChangeNotifier + InheritedWidget, Navigator 1.0)
  server/   auth_server.dart            routes, attestation + signature verification, audit
            policy.dart                 requireAttestation, security levels, package, TTLs
            models.dart                 records, canonical payload, recovery codes, routes
  client/   auth_client.dart            register / recover / retry upload / login / unbind
            outcome.dart                Success | NeedsRebind | Retryable | Blocked | Rejected
            preflight.dart, reconcile.dart, accounts.dart, aliases.dart
  screens/  accounts, register, attestation_report, login (signing trace), session,
            account_detail, recovery, preflight, server_console
test/       auth_server_test.dart (protocol), flows_widget_test.dart (UI on a fake platform)
```

Shared code comes from `../example/packages/examples_shared`:

- the attestation verifier;
- signature verification;
- canonical JSON;
- `MockTransport`, `ChallengeStore` and `AuditLog`;
- the UI widgets;
- `SoftwareBiometricPlatform`, used by the tests.

## Run it

```sh
flutter run            # a physical Android device shows real attestation
flutter test           # server protocol + widget flows on a software fake
```

The Android emulator's keystore usually returns a software-rooted chain or `notSupported`:

- With a software-rooted chain, the server rejects the registration. The report marks the failing root check.
- With `notSupported`, the app explains that the device cannot attest.

Both are the correct outcome. To continue on an emulator, turn off **Require attestation** in the server console. The emulator then registers as "Untrusted" (after a software-rooted chain) or "Not attested" (after `notSupported`).

## Try this

1. **Register.** Tap *Create account*, then enter a username and accept the prompt. On a physical Android device, the report shows the tier (TEE or StrongBox), the challenge match, the attested package `com.example.passwordless_login_example`, `userAuthType`, the boot state, and "Revocation not checked". Save the recovery code.
2. **Sign in.** The signing trace shows five steps:
   - the nonce;
   - the key alias;
   - the exact canonical JSON that was signed;
   - the signature, with the reported `authenticationType` and a note on how far to trust it;
   - each check the server ran.
3. **Break it from the console** (the terminal icon, then *Faults*):
   - *Tamper with the next login signature* → "ECDSA signature mismatch" (an RSA mismatch on Windows).
   - *Present the next login as another user* → "challenge bound to a different subject".
   - *Expire the next login nonce* → "challenge expired".
   - *Replay the last login* → "challenge already used (replay)".
   - *Fail the next registration upload*, then register → the key is kept. *Retry upload* re-reads the chain with `getKeyInfo`, and the server accepts it because it had not consumed the challenge yet.
4. **Invalidate the key.** Enroll a new fingerprint or face in system Settings, then sign in. You get `keyInvalidated` and "This device needs a new key". *Re-bind* first asks to delete the old key, because `failIfExists` protected it. Then enter the recovery code. The server verifies a fresh attestation, marks the old key *superseded*, and shows a new code.
5. **Change the policy.** On iOS, macOS or Windows, registration is rejected. Turn *Require attestation* off in *Policy* to register as "Not attested". Deselect TEE to accept StrongBox keys only.
6. **Use several accounts.** Register a second username. Each account has its own `acct_…` alias, and *Remove from this device* signs an unbind request that affects only that account.
7. **Wipe and restore.** *Wipe device keys* calls `deleteAllKeys`. The server's records then show as *orphaned* under *Records*, and *Recover with a code* binds the device again.

## What a real server must add

- **Revocation.** Check every certificate serial in the chain against `https://android.googleapis.com/attestation/status`. The report always says "Revocation not checked".
- **App signing certificate.** Pin your release signing-certificate SHA-256 in `AttestationPolicy.expectedSigningCertificateDigests`. The package name alone is easy to copy.
- **Root updates.** Keep Google's attestation roots current (`tool/update_google_roots.dart` in `examples_shared`).
- **TLS** for every request, and **rate limiting**, especially on `/recovery/*` and `/login/begin`.
- **Durable storage.** Challenges, sessions and the audit log need shared, persistent storage with atomic "consume once" semantics. A lost upload response should be handled deliberately; this demo rejects the replayed request.
- **Stronger recovery.** Use a slow KDF if codes are ever user-chosen, notify the user when a code is used, and consider a waiting period.
- **Origin binding, if you need phishing resistance.** Use platform passkeys (FIDO2 / WebAuthn), where the OS binds each signature to the relying party's origin. The `rp` string here is only a label.
