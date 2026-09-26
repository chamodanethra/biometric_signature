# Passwordless Login Example

A complete passwordless authentication system using biometric signatures for secure, convenient user authentication, with comprehensive lifecycle management and error handling.

## Features

- 🔐 Passwordless authentication flow
- 👤 User registration with biometric enrollment
- ✅ Secure login using biometric signatures
- 🔄 Challenge-response authentication protocol
- 🎯 Session management
- 🔒 Hardware-backed security
- ⚠️ **Complete error handling** for all biometric states
- 🔄 **Biometric re-enrollment** flow for key invalidation
- 🔑 **Device credential fallback** (PIN/passcode/pattern)
- ⚙️ **Account settings** for biometric management
- 🔍 **Key status monitoring** and validation
- 🧪 **Test authentication** feature

## How It Works

### Registration Flow
1. User provides username/email
2. User configures security options:
   - Device credential fallback
   - Key invalidation on biometric changes
3. App generates cryptographic key pair in secure hardware
4. Public key is sent to server and stored with user profile
5. User can now login using biometrics

### Login Flow
1. User enters username
2. Server sends a time-limited challenge (nonce)
3. User authenticates with biometrics
4. App signs the challenge with private key
5. Server verifies signature with stored public key
6. On success, server issues session token

### Error Handling
The example demonstrates handling all biometric error scenarios:
- **User Canceled**: Simple retry
- **Key Invalidated**: Guided re-enrollment flow
- **Locked Out**: Temporary lockout with retry guidance
- **Locked Out Permanent**: Must use device credential
- **Not Enrolled**: Guide user to device settings
- **Not Available**: Inform user of hardware/setup requirements
- **Key Not Found**: Offer re-enrollment

### Re-enrollment Flow
1. Detect key invalidation (e.g., user added new fingerprint)
2. Show explanation dialog
3. Delete old invalidated keys
4. Create new keys with same security settings
5. Update server with new public key
6. User can login again

## Security Features

- **No passwords stored**: Eliminates password-related vulnerabilities
- **Phishing resistant**: Challenge-response protocol prevents replay attacks
- **Hardware-backed**: Private keys never leave secure hardware (Secure Enclave/StrongBox)
- **Biometric gating**: Every authentication requires user presence
- **Time-limited challenges**: Nonces expire to prevent reuse
- **Key invalidation**: Optional setting to invalidate keys when biometrics change
- **Device credentials**: Optional fallback for locked-out scenarios

## Architecture

```
┌─────────────┐           ┌─────────────┐
│   Flutter   │           │   Server    │
│     App     │◄─────────►│  (Simulated)│
└─────────────┘           └─────────────┘
      │                          │
      ├─ Registration            │
      │  1. Configure Settings   │
      │  2. Generate Keys        │
      │  3. Send Public Key ────►│
      │  4. Store User ◄─────────┤
      │                          │
      ├─ Login                   │
      │  1. Request Challenge ──►│
      │  2. Receive Nonce ◄──────┤
      │  3. Sign with Biometric  │
      │  4. Send Signature ─────►│
      │  5. Verify & Token ◄─────┤
      │                          │
      ├─ Re-enrollment           │
      │  1. Delete Old Keys      │
      │  2. Create New Keys      │
      │  3. Update Public Key ──►│
      │                          │
      ▼                          ▼
[Secure Enclave]         [User Database]
```

## Screens

### 1. Login Screen
- Username entry
- Biometric authentication
- Comprehensive error dialogs:
  - Key invalidated → Re-enrollment dialog
  - Locked out → Retry guidance
  - Not enrolled → Setup instructions
  - Not available → Hardware info
- Registration link

### 2. Registration Screen
- Username and email input
- Security configuration:
  - Device credential fallback toggle
  - Key invalidation on changes toggle
- Biometric availability check
- Consent dialog with configuration summary

### 3. Home Screen
- User account information
- Security status display:
  - Biometric authentication status
  - Device credentials enabled/disabled
  - Hardware security active
  - Key invalidation setting
- Settings button
- Logout

### 4. Settings Screen
- **Account Section**: User info, last re-enrollment timestamp
- **Biometric Status**: Availability, enrolled biometrics
- **Key Status**: Exists, valid, algorithm, key size
- **Configuration**: Device credentials, key invalidation setting
- **Actions**:
  - Test Biometric: Verify authentication works
  - Re-enroll Biometrics: Create new keys
  - Delete Account: Remove all data and keys

## API Simulation

This example simulates a backend server locally. In production:

- Replace with actual REST API calls
- Implement proper server-side signature verification
- Use secure token management (JWT, OAuth)
- Add rate limiting and security measures
- Implement proper session invalidation
- Add multi-device support
- Implement account recovery mechanisms

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
- Apps requiring FIDO2/WebAuthn compliance

## Advantages Over Passwords

1. **Better Security**: No password theft, phishing, or credential stuffing
2. **Better UX**: No remembering passwords, faster login
3. **Lower Support Costs**: No password reset flows
4. **Compliance**: Meets modern authentication standards
5. **Future-proof**: Aligns with FIDO2/WebAuthn standards
6. **Better Error Recovery**: Clear guidance for all error states
7. **Device Flexibility**: Optional fallback to device credentials

## Configuration Options

### Device Credential Fallback
When enabled, users can authenticate with PIN/pattern/passcode instead of biometrics if:
- They are temporarily locked out
- Biometric sensor is unavailable
- They prefer to use their passcode

### Key Invalidation on Biometric Changes
When enabled (recommended), biometric keys are invalidated if:
- New fingerprints/faces are enrolled
- Existing biometrics are removed
- Provides protection against attackers who enroll their own biometrics

## Testing Scenarios

1. **Happy Path**: Register → Login → Use app
2. **Key Invalidation**: Add new fingerprint → Login → Re-enroll
3. **Lockout**: Multiple failed attempts → Wait or use device credential
4. **No Biometrics**: Remove all biometrics → See error guidance
5. **Settings**: View key status → Test auth → Re-enroll

## Notes

- This example simulates server-side logic locally
- In production, implement proper backend infrastructure
- Consider implementing account recovery mechanisms
- Add multi-device support for complete solution
- Comply with data protection regulations (GDPR, etc.)
- Test all error scenarios on real devices
- Consider platform-specific biometric behaviors

## Error Code Reference

| Code | Meaning | User Action |
|------|---------|-------------|
| `success` | Operation successful | Continue |
| `userCanceled` | User cancelled | Retry |
| `keyInvalidated` | Biometrics changed | Re-enroll |
| `lockedOut` | Too many failed attempts (temporary) | Wait or use device credential |
| `lockedOutPermanent` | Locked out permanently | Must use device credential |
| `notEnrolled` | No biometrics on device | Enroll in device settings |
| `notAvailable` | Biometric hardware unavailable | Check device capability |
| `keyNotFound` | Biometric key missing | Re-enroll |

## Implementation Highlights

### AuthService
- `register()`: Accepts security configuration options
- `authenticateWithChallenge()`: Returns SignatureResult for error handling
- `reEnrollBiometrics()`: Handles key invalidation recovery
- `getBiometricStatus()`: Checks device capability
- `getKeyStatus()`: Checks key validity

### Models
- `User`: Extended with `allowDeviceCredentials`, `keyInvalidatedOnEnrollmentChange`, `lastReEnrollment`
- `AuthChallenge`: Time-limited nonce for authentication
- `AuthSession`: Session token management

### Error Handling Pattern
```dart
final result = await authService.authenticateWithChallenge(...);
if (result.code != BiometricError.success) {
  await _handleBiometricError(result, username);
  return;
}
// Continue with success flow
```
