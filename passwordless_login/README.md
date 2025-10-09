# Passwordless Login Example

A complete passwordless authentication system using biometric signatures for secure, convenient user authentication.

## Features

- 🔐 Passwordless authentication flow
- 👤 User registration with biometric enrollment
- ✅ Secure login using biometric signatures
- 🔄 Challenge-response authentication protocol
- 🎯 Session management
- 🔒 Hardware-backed security

## How It Works

### Registration Flow
1. User provides username/email
2. App generates cryptographic key pair in secure hardware
3. Public key is sent to server and stored with user profile
4. User can now login using biometrics

### Login Flow
1. User enters username
2. Server sends a time-limited challenge (nonce)
3. User authenticates with biometrics
4. App signs the challenge with private key
5. Server verifies signature with stored public key
6. On success, server issues session token

## Security Features

- **No passwords stored**: Eliminates password-related vulnerabilities
- **Phishing resistant**: Challenge-response protocol prevents replay attacks
- **Hardware-backed**: Private keys never leave secure hardware
- **Biometric gating**: Every authentication requires user presence
- **Time-limited challenges**: Nonces expire to prevent reuse

## Architecture

```
┌─────────────┐           ┌─────────────┐
│   Flutter   │           │   Server    │
│     App     │◄─────────►│  (Simulated)│
└─────────────┘           └─────────────┘
      │                          │
      ├─ Registration            │
      │  1. Generate Keys        │
      │  2. Send Public Key ────►│
      │  3. Store User ◄─────────┤
      │                          │
      ├─ Login                   │
      │  1. Request Challenge ──►│
      │  2. Receive Nonce ◄──────┤
      │  3. Sign with Biometric  │
      │  4. Send Signature ─────►│
      │  5. Verify & Token ◄─────┤
      │                          │
      ▼                          ▼
[Secure Enclave]         [User Database]
```

## API Simulation

This example simulates a backend server locally. In production:

- Replace with actual REST API calls
- Implement proper server-side signature verification
- Use secure token management (JWT, OAuth)
- Add rate limiting and security measures

## Setup

1. Navigate to the passwordless_login directory:
```bash
cd passwordless_login
```

2. Get dependencies:
```bash
flutter pub get
```

3. Run the app:
```bash
flutter run
```

## Use Cases

- Mobile banking apps
- Enterprise applications
- Healthcare systems
- Government services
- High-security applications
- User-friendly authentication

## Advantages Over Passwords

1. **Better Security**: No password theft, phishing, or credential stuffing
2. **Better UX**: No remembering passwords, faster login
3. **Lower Support Costs**: No password reset flows
4. **Compliance**: Meets modern authentication standards
5. **Future-proof**: Aligns with FIDO2/WebAuthn standards

## Notes

- This example simulates server-side logic locally
- In production, implement proper backend infrastructure
- Consider implementing account recovery mechanisms
- Add multi-device support for complete solution
- Comply with data protection regulations (GDPR, etc.)

