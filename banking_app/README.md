# Step-up Banking — `biometric_signature` example

Step-up transaction signing with two keys on one device:

- **`device_binding`** is a silent key (`requireAuthentication: false`). It
  signs every API request without a prompt. That proves the request comes
  from this device, and nothing more.
- **`txn_approval`** is a biometric key. It signs the exact bytes of larger
  transfers after a biometric prompt. It is invalidated when fingerprints or
  faces change.

A mock bank runs in the same process. It verifies every signature, checks
Android key attestation and decides a risk tier for each transfer. It also
has a console for injecting attacks.

> **Demo code, not production code.** The "server" is an in-process mock
> behind a fake network. It stores records in SharedPreferences, sends
> one-time codes to a simulated SMS card, and does not check attestation
> certificate revocation. See [What a real server must add](#what-a-real-server-must-add).

## The story

1. **Bind the device.** The preflight calls `biometricAuthAvailable()` and
   `isDeviceLockSet()`. The bank then sends a one-time code (simulated SMS)
   and two single-use attestation challenges. The app creates both keys, and
   on Android each key is attested. The enrollment request is signed by the
   new `device_binding` key, which proves possession of it. The bank verifies
   the attestation chains and records what they prove.
2. **Use the bank.** Every call (accounts, prepare, confirm …) is signed
   silently by `device_binding` over:

   ```text
   METHOD\nPATH\nTIMESTAMP\nsha256(canonical body)\nrequestId
   ```

   The bank rejects a request if:
   - the timestamp is more than ±60 s from its clock,
   - the request id was seen before (replay cache), or
   - the signature does not match.

   The **Signed requests** screen lists each request with the bank's verdict.
3. **Transfer: what you see is what you sign.** `/transfers/prepare` returns
   canonical JSON bytes that the bank built:
   `{v, txnId, amountCents, currency, fromAccount, payee, payeeAccount,
   nonce, iat, exp, tier, deviceKey}`.

   The app decodes those bytes strictly. It refuses unknown fields, missing
   fields and non-canonical encodings such as duplicate keys. It shows exactly
   those fields, then signs the same bytes with `createSignatureFromBytes`.

   On `/transfers/confirm` the bank:
   - checks that the signed bytes are the bytes it issued (it never
     re-serializes the client's copy),
   - consumes the nonce (single use) and checks the expiry,
   - verifies the signature with the key the tier requires,
   - records `authenticationType` and flags anomalies,
   - posts to the ledger.

   The receipt shows every check.
4. **Recover.** Enrolling a new fingerprint or face invalidates `txn_approval`
   (`keyInvalidated`), which locks approvals. `device_binding` has no
   user-authentication constraint, so enrollment changes do not affect it.
   Re-verification works like this:
   - a silent `device_binding` request proves it is the same device;
   - a one-time code proves it is the same person;
   - a new, attested `txn_approval` key is registered;
   - the bank revokes the old key.

   If `device_binding` itself is gone (`keyNotFound`), the device must be
   bound again.

```mermaid
sequenceDiagram
    participant U as User
    participant A as App
    participant P as biometric_signature
    participant B as Mock bank
    A->>B: POST /transfers/prepare (signed by device_binding, silent)
    B->>B: verify request (±60 s, request id, signature), decide tier
    B-->>A: payload bytes (canonical JSON) + tier
    A->>U: show the decoded fields
    U->>P: approve (biometric prompt for tiers B/C)
    P-->>A: signature over the exact bytes
    A->>B: POST /transfers/confirm (payload, signature; request signed by device_binding)
    B->>B: bytes == issued? nonce unused? not expired? right key? signature valid?
    B-->>A: accepted/rejected + verification trace
```

## Keys

| Alias | `createKeys` config | Signs | What it proves |
|---|---|---|---|
| `device_binding` | `signatureType: ecdsa`, `requireAuthentication: false`, `failIfExists: true`, `attestationChallenge` (Android) | Every request (`createSignature`, text); tier A payloads (`createSignatureFromBytes`) | The request comes from the bound device. Nothing about the user: code running inside the app can use this key without the user, so it cannot satisfy strong-customer-authentication inherence on its own. |
| `txn_approval` | `signatureType: ecdsa`, `enforceBiometric: true`, `setInvalidatedByBiometricEnrollment: true`, `useDeviceCredentials` (user choice, default off), prompt texts, `failIfExists: true`, `attestationChallenge` (Android) | Tier B and C payloads (`createSignatureFromBytes` + `CreateSignatureConfig`) | A key protected by user authentication approved these exact bytes. On Android, the attestation shows whether the hardware enforces biometric-only use (`userAuthType` 2) or biometric-or-PIN (3). |

Keys are ECDSA P-256 with SHA-256. On Windows, Windows Hello keys are
RSA-2048 (PKCS#1 v1.5, SHA-256). The bank picks the algorithm from the
registered public key.

## Risk tiers

The rules live in `lib/server/risk_policy.dart` and can be edited in the
server console → **Policy** tab.

| Tier | Default amount | Requirement |
|---|---|---|
| A | ≤ $100 | Silent `device_binding` signature. Possession only, which is why the limit is low. |
| B | ≤ $2,000 | `txn_approval` signature (biometric prompt). |
| C | > $2,000 | `txn_approval`, and the key's Android attestation must prove it is biometric-only: hardware-enforced `userAuthType == 2` with no `noAuthRequired` (`AttestationReport.attestsBiometricOnly`). |

"Require attested biometric-only key for tier C" is **on** by default:

- iOS, macOS and Windows cannot attest keys, so they are capped at tier B.
  The app explains this in a banner and in the tier preview.
- An Android key created with the PIN fallback is attested as `userAuthType 3`,
  so it is also capped at tier B.

Turning the toggle off lets tier C accept an unattested key that was
*declared* biometric-only. The trace labels this "declared, unverified".

`authenticationType` is reported by the client and is not signed. The bank
records it for audit and never bases trust on it. If a key that is attested
(or declared) biometric-only reports `credential`, the transfer is accepted
but flagged as an anomaly. The attested key policy is what the hardware
enforces.

## Server console

Tap the terminal icon in any app bar to open the console. It has five tabs:

- **Records** — accounts, device records with each key's trust tier, pending
  approvals, decided transfers (with anomaly flags) and the simulated SMS
  outbox.
- **Audit** — the bank's audit trail.
- **Wire** — every request and response on the mock network, with injected
  faults.
- **Policy** — tier limits, the tier C attestation toggle, the timestamp
  window (±30 s / ±60 s / ±5 min) and the approval window.
- **Faults** — see the table below, plus **Reset demo**, which calls
  `deleteAllKeys()`, clears the client and server stores and reseeds the
  accounts.

| Fault | Who | What stops it |
|---|---|---|
| Tamper amount on next confirm | Network attacker | The `device_binding` request signature (sha256 of the body changed). |
| Replay last confirm | Network attacker | The replay cache (request id already used). |
| Change amount after approval | Compromised app | For tier B/C, the approval signature no longer matches and the bytes are not the issued bytes. For tier A, the malware re-signs with the silent key, so the signature verifies, but the bytes are still not the ones the bank issued. |
| Re-submit last approval | Compromised app (fresh request id and timestamp) | The payload nonce is single-use. |
| Device clock skew (±90 s, ±5 min) | Environment | The ±60 s timestamp window. |
| Fail next request | Environment | Nothing to stop: it shows network-error handling and retry. |

## APIs and flags used

| API / field | Where |
|---|---|
| `biometricAuthAvailable`, `isDeviceLockSet` | Onboarding preflight (`client/key_setup.dart`) |
| `createKeys` with `requireAuthentication: false`, `failIfExists`, `attestationChallenge` | `device_binding` (`KeySetup.createDeviceBindingKey`) |
| `createKeys` with `enforceBiometric`, `setInvalidatedByBiometricEnrollment`, `useDeviceCredentials`, `promptSubtitle` / `promptDescription` / `cancelButtonText`, `failIfExists`, `attestationChallenge` | `txn_approval` (`KeySetup.createApprovalKey`) |
| `KeyCreationResult.attestationCertificateChain` | Sent to the bank and verified with `AttestationVerifier` (`server/bank_server.dart`) |
| `createSignature` (text payload) | Request signing (`client/bank_client.dart`, `signRequest`) |
| `createSignatureFromBytes` + `CreateSignatureConfig` (`promptSubtitle`, `promptDescription`, `cancelButtonText`, `allowDeviceCredentials`), `promptMessage` | Transfer approval (`client/approval_service.dart`) |
| `SignatureResult.authenticationType` | Recorded by the bank; anomaly flag |
| `getKeyInfo(checkValidity: true)` via `probeKey` | Launch reconciliation, after unexpected failures, security screen (`client/session.dart`) |
| `deleteKeys` | Replacing a leftover key, rotating the approval key, "Delete on this device", unbinding |
| `deleteAllKeys` | Reset demo |

| `BiometricError` | Handling |
|---|---|
| `keyAlreadyExists` | Onboarding offers to replace the leftover key. The bank has no record of it, and `failIfExists` refused to overwrite it silently. |
| `notSupported` (with `attestationChallenge`) | Android keystores that cannot attest: the key is created again unattested and capped at tier B. |
| `notAvailable` (with `attestationChallenge`) | Transient. Retry with a fresh challenge, or continue unattested. |
| `keyInvalidated` / `keyNotFound` on `txn_approval` | Approvals lock; re-verify. |
| `keyNotFound` on `device_binding` | The binding is lost; bind the device again. The bank retires the old record. |
| `userCanceled` / `systemCanceled` | "Not approved"; nothing is sent. |
| `passcodeNotSet` / `notEnrolled` | Back to the preflight. |
| Everything else | `guidanceFor(code)` from the shared package. |

## Platform differences

| | Android | iOS / macOS | Windows |
|---|---|---|---|
| Silent `device_binding` | Silent | Silent | **Windows Hello prompts for every request.** A banner explains this, auto-refresh is off, and you pull to refresh. |
| Key type | EC P-256 (TEE / StrongBox) | EC P-256 (Secure Enclave) | RSA-2048 (Windows Hello) |
| Attestation | Yes: TEE / StrongBox verified to Google's roots | No: `notSupported`. The app does not send a challenge, and the key is registered unattested. | No |
| Max tier with the default policy | C (biometric-only key) or B (PIN fallback) | B | B |
| Prompt text | `promptMessage` as the title, plus subtitle, description and cancel text | Only `promptMessage`, so it carries the amount and payee | `promptMessage` |
| `authenticationType` | Reported by the OS | Inferred from the key policy | Always `unknown` |
| Invalidation on enrollment change | Yes | Yes, except keys with the PIN/passcode fallback | No |

## Try this

1. **Bind.** Tap Send code → Use code → Create keys & bind device. On
   Android, open Security → View attestation report for each key:
   `device_binding` shows `noAuthRequired`, and `txn_approval` shows
   `userAuthType` 2.
2. **Tier A.** Transfer $45 to Alice. There is no prompt. The receipt's
   trace says "Silent device_binding key: no user authentication".
3. **Tier B.** Transfer $1,250. The biometric prompt reads "Pay $1,250.00 to
   Alice Chen" (on iOS, "Approve $1,250.00 to Alice Chen").
4. **Tier C.** Transfer $2,400:
   - On Android with a biometric-only key, it is accepted.
   - On iOS, macOS or Windows, it is declined and the preview explains why.
   - Turn the tier C toggle off in the console and try again: it is accepted
     as "declared, unverified".
5. **Tamper.** Console → Faults → Tamper amount on next confirm, then make a
   transfer. It is rejected with a request signature mismatch.
6. **Compromised app.** Console → Change amount after approval, then make a
   tier B transfer. It is rejected with an approval signature mismatch. Try
   it with tier A: the silent re-signature verifies, but the bytes were not
   issued by the bank.
7. **Replay.** After an accepted transfer, try both:
   - Console → Replay last confirm is rejected because the request id was
     already used.
   - Re-submit last approval is rejected because the nonce was already used.
8. **Clock skew.** Set the device clock to +90 s, then pull to refresh. The
   request is rejected by the ±60 s check. Set it back to 0.
9. **Enrollment change.** Enroll a new fingerprint or face in system settings
   (in the iOS Simulator, toggle Features → Face ID → Enrolled off and on).
   Return to the app. Approvals are locked, but tier A still works. Tap
   Re-verify → Send code → Use code → Create new key & finish. The console
   shows the old key revoked.
10. **Reset demo** starts over.

## Running and testing

```sh
flutter run            # Android, iOS, macOS or Windows
flutter test           # server, request signing, risk policy, payload and widget flows
```

The tests replace the plugin with `SoftwareBiometricPlatform` from
`examples_shared`, which uses real cryptography and synthetic attestation
chains. They also use in-memory stores, a manual clock and zero latency.
`test/support/harness.dart` wires it all together.

## Code map

```text
lib/
  main.dart, app.dart, services.dart   app shell, AppScope, composition root
  money.dart                           integer cents, $1,250.00 formatting
  server/                              the mock bank (pure Dart)
    bank_server.dart                   routes: enroll, accounts, prepare, confirm, reverify, unbind
    request_signing.dart               canonical request string + RequestVerifier (skew, replay, signature)
    risk_policy.dart                   tiers A/B/C and tier C eligibility
    ledger.dart, models.dart           accounts, payees, postings, device/key/transfer records
  client/
    bank_client.dart                   signed calls, request log, compromised-app faults
    key_setup.dart                     preflight, key creation, enrollment and re-verification flows
    approval_service.dart              signs payload bytes with the tier's key, classifies errors
    transaction_payload.dart           strict decoder for the signed payload
    session.dart                       client state and launch reconciliation
  screens/                             onboarding, home, transfer, approve, receipt,
                                       request log, security, re-verify, server console
```

## What this demo does not claim

It is **not**:
- FIDO or WebAuthn,
- a passkey,
- phishing-resistant,
- evidence of non-repudiation.

The prompt text comes from the app, so a compromised app can lie in it. What
the bank can rely on is narrower:
- a key protected by user authentication (and on Android, attested as
  biometric-only) signed the exact bytes the bank issued;
- that signature was fresh (single-use nonce) and came from the bound device.

## What a real server must add

- **Revocation.** Check every attestation certificate against
  <https://android.googleapis.com/attestation/status>, and keep the roots
  current.
- **Release signing-certificate pinning.** Set
  `AttestationPolicy.expectedSigningCertificateDigests` to the release
  signing key. Optionally require a locked bootloader.
- **TLS** for every call, and certificate pinning if you need it.
- **Rate limits** on one-time codes, logins and transfers, plus velocity
  limits on tier A.
- **Durable, transactional storage** for records, nonces and the replay
  cache (these are in memory here), and idempotent posting.
- **A real out-of-band step-up channel** for re-verification (not a
  simulated SMS), and an identity check before binding a device.
- **Monitoring** of anomaly flags and attestation downgrades, and a way for
  customers to see and revoke their bound devices.
