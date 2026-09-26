# examples_shared

Shared code for the `biometric_signature` example apps (`example/`,
`passwordless_login/`, `banking_app/`, `secure_vault/`). It is an unpublished
local package (`publish_to: none`); the apps depend on it by path.

**This is demo code, not production code.** The "server" runs inside the app,
attestation revocation is not checked, and storage is `SharedPreferences`. It
exists to show what a real server has to verify.

## Entry points

| Library | Flutter? | What it contains |
|---|---|---|
| `package:examples_shared/crypto.dart` | no | Public-key normalization (base64 / PEM / hex → SPKI DER), DER reader/encoder, canonical JSON, signature verification (RSA PKCS#1 v1.5, ECDSA, never throws), RSA-OAEP with separate MGF1 digest, Android and Apple ECIES, `EncryptionTarget` (which scheme a device key needs), envelope encryption. |
| `package:examples_shared/attestation.dart` | no | X.509 parsing, Android key attestation `KeyDescription`, chain validation up to Google's roots (trusted by public-key hash), `AttestationVerifier` → `AttestationReport`. |
| `package:examples_shared/server.dart` | `shared_preferences` only | `MockTransport` (JSON round trip, latency, wire log, fault injection), `ChallengeStore`, `ReplayCache`, `KeyValueStore` (in-memory / `SharedPreferences`), `AuditLog`, `Clock`. |
| `package:examples_shared/ui.dart` | yes | Theme and `StatusColors`, widgets (`AttestationReportView`, `WireLogView`, `ErrorBanner`, `DevConsoleScaffold`, …), `currentDevicePlatform()` and `PlatformCapabilities`, `guidanceFor(BiometricError)`, `probeKey`. |
| `package:examples_shared/testing.dart` | yes | `SoftwareBiometricPlatform` (a fake plugin platform with real crypto), synthetic attestation chains, a certificate builder. |

## Ground rules the code follows

- The plugin's `publicKey` is SubjectPublicKeyInfo DER on every platform; only
  its text encoding differs. Verify against it, not `publicKeyBytes`.
- Signatures are RSA PKCS#1 v1.5 / SHA-256 or DER ECDSA P-256 / SHA-256.
  High-S ECDSA signatures are valid (no platform normalizes S).
- `decrypt()` returns UTF-8 text, so binary data (such as envelope data keys)
  is base64-encoded before encryption.
- ECIES and RSA-OAEP parameters differ between Android and Apple; use
  `EncryptionTarget.resolve` instead of choosing a scheme by hand.
- Nothing here provides non-repudiation or phishing resistance.

## Tests and tools

`test/` (not shipped) checks everything against third-party data: Google's
`android/keyattestation` test chains, OpenSSL signatures and OAEP ciphertexts,
and ECIES / OAEP vectors produced by the Apple Security framework and by a JCA
port of the plugin's Android code. `tool/` (not shipped) holds the generators:

- `tool/gen_vectors.py` — OpenSSL signature and OAEP vectors.
- `tool/gen_apple_vectors.swift` — Apple ECIES / OAEP vectors (macOS).
- `tool/AndroidVectors.java` — Android ECIES / OAEP vectors (JDK 11+).
- `tool/cross_check_payloads.dart` — encrypts with the Dart code so the Swift
  and Java tools can decrypt it.
- `tool/update_google_roots.dart` — re-fetches Google's attestation roots.
