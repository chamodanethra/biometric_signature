# Biometric Signature Examples

This repository contains comprehensive real-world examples demonstrating the biometric_signature plugin in action.

## 📱 Available Examples

### 1. Basic Example (`example/`)
**Difficulty**: Beginner  
**Purpose**: Simple demonstration of core plugin features

A minimal example showing basic key generation, signature creation, and key management.

**Features**:
- Toggle between RSA and ECDSA algorithms
- Create biometric keys
- Sign payloads
- View public keys and signatures

**Run**:
```bash
cd example
flutter run
```

---

### 2. Banking App (`banking_app/`)
**Difficulty**: Intermediate  
**Purpose**: Secure transaction signing for financial applications

A complete banking application demonstrating secure transaction signing using biometric authentication.

**Features**:
- 💰 Account balance management
- 💸 Money transfers between accounts
- 🔐 Biometric transaction signing
- 📝 Transaction history
- ✅ Server-side verification (simulated)

**Key Concepts**:
- Challenge-response protocol for transactions
- Cryptographic proof of transaction authorization
- Hardware-backed security for financial operations
- Non-repudiation through biometric signatures

**Run**:
```bash
cd banking_app
flutter pub get
flutter run
```

**[View Full Documentation →](banking_app/README.md)**

---

### 3. Document Signer (`document_signer/`)
**Difficulty**: Intermediate  
**Purpose**: Digital document signing with biometric authentication

A document signing application for secure authentication of legal documents, contracts, and agreements.

**Features**:
- 📄 Create and manage documents
- ✍️ Sign documents with biometrics
- 🔐 Cryptographic signature verification
- 📋 Document library with signing status
- 📤 Export signed documents

**Key Concepts**:
- Document integrity through hashing
- Digital signatures for authenticity
- Non-repudiation for legal documents
- Audit trail with timestamps
- Tamper-evident signatures

**Run**:
```bash
cd document_signer
flutter pub get
flutter run
```

**[View Full Documentation →](document_signer/README.md)**

---

### 4. Passwordless Login (`passwordless_login/`)
**Difficulty**: Advanced  
**Purpose**: Complete passwordless authentication system with full lifecycle management

A full-featured passwordless authentication system demonstrating the complete lifecycle of biometric authentication, including error handling, recovery flows, and account management.

**Features**:
- 🔐 Passwordless registration and login
- 👤 User account management
- ✅ Challenge-response authentication
- 🔄 Session management
- 🎯 Secure token handling
- ⚠️ Comprehensive error handling (locked out, key invalidated, etc.)
- 🔄 Biometric re-enrollment flow
- 🔑 Device credential fallback option
- ⚙️ Account settings and configuration
- 🔍 Key status monitoring
- 🧪 Test authentication feature

**Key Concepts**:
- FIDO2/WebAuthn-style authentication
- Challenge-response protocol
- Server-side signature verification
- Public key infrastructure
- Phishing-resistant authentication
- Error recovery and re-enrollment
- Biometric lifecycle management
- Hardware-backed key storage

**Run**:
```bash
cd passwordless_login
flutter pub get
flutter run
```

**[View Full Documentation →](passwordless_login/README.md)**

---

## 🎯 Which Example Should I Start With?

### For Learning the Plugin
Start with **Basic Example** (`example/`) → then explore others based on your use case

### For Financial Applications
**Banking App** - Shows transaction signing and payment authorization

### For Document Management
**Document Signer** - Shows document authentication and legal signing

### For User Authentication
**Passwordless Login** - Shows modern authentication without passwords

## 🔐 Security Features Demonstrated

All examples demonstrate:
- ✅ Hardware-backed key storage (StrongBox/Secure Enclave)
- ✅ Private keys never leave secure hardware
- ✅ Biometric authentication for every sensitive operation
- ✅ Cryptographic signatures for non-repudiation
- ✅ Platform-specific best practices

## 📚 Learning Path

```
1. Basic Example
   ↓
   Learn: Core API, key generation, signing basics
   
2. Choose your path:
   
   Path A: Financial Apps
   └── Banking App
       Learn: Transaction security, verification flows
   
   Path B: Document Management
   └── Document Signer
       Learn: Document integrity, legal signatures
   
   Path C: Authentication
   └── Passwordless Login
       Learn: Challenge-response, session management

3. Build Your Own
   Combine concepts from multiple examples
```

## 🛠️ Common Code Patterns

### Initialize Biometric Service
```dart
import 'package:biometric_signature/biometric_signature.dart';

final biometric = BiometricSignature();

// Check availability
final availability = await biometric.biometricAuthAvailable();
if (availability.canAuthenticate ?? false) {
  print('Biometrics available: ${availability.availableBiometrics}');
}

// Create keys (RSA by default)
final keyResult = await biometric.createKeys(
  keyFormat: KeyFormat.pem,
  promptMessage: 'Authenticate to create keys',
  config: CreateKeysConfig(
    signatureType: SignatureType.rsa,
    useDeviceCredentials: true,
    setInvalidatedByBiometricEnrollment: true,
    enforceBiometric: true,
    enableDecryption: false, // Android only
  ),
);

if (keyResult.code == BiometricError.success) {
  print('Public Key: ${keyResult.publicKey}');
}
```

### Get Key Info
```dart
// Check key existence with metadata
final info = await biometric.getKeyInfo(
  checkValidity: true,
  keyFormat: KeyFormat.pem,
);

if (info.exists && (info.isValid ?? true)) {
  print('Algorithm: ${info.algorithm}, Size: ${info.keySize} bits');
  print('Hybrid Mode: ${info.isHybridMode}');
  print('Public Key: ${info.publicKey}');
}
```

### Sign Data
```dart
final result = await biometric.createSignature(
  payload: 'data_to_sign',
  promptMessage: 'Authenticate to sign',
  signatureFormat: SignatureFormat.base64,
  keyFormat: KeyFormat.pem,
  config: CreateSignatureConfig(
    allowDeviceCredentials: true,
  ),
);

if (result.code == BiometricError.success) {
  print('Signature: ${result.signature}');
}
```

### Decrypt Data
```dart
final decryptResult = await biometric.decrypt(
  payload: encryptedBase64,
  payloadFormat: PayloadFormat.base64,
  promptMessage: 'Authenticate to decrypt',
  config: DecryptConfig(
    allowDeviceCredentials: false,
  ),
);

if (decryptResult.code == BiometricError.success) {
  print('Decrypted: ${decryptResult.decryptedData}');
}
```

### Error Handling
```dart
final result = await biometric.createSignature(
  payload: 'data_to_sign',
  promptMessage: 'Authenticate',
);

switch (result.code) {
  case BiometricError.success:
    print('Signed: ${result.signature}');
    break;
    
  case BiometricError.userCanceled:
    print('User cancelled authentication');
    break;
    
  case BiometricError.keyInvalidated:
    print('Key invalidated - biometrics changed, re-enrollment required');
    // Show re-enrollment dialog to user
    break;
    
  case BiometricError.lockedOut:
    print('Temporarily locked out - too many attempts');
    // Show retry message or device credential option
    break;
    
  case BiometricError.lockedOutPermanent:
    print('Permanently locked out - must use device credential');
    // Require device passcode/PIN to unlock
    break;
    
  case BiometricError.notEnrolled:
    print('No biometrics enrolled - user must enroll in settings');
    break;
    
  case BiometricError.notAvailable:
    print('Biometric hardware not available on this device');
    break;
    
  case BiometricError.keyNotFound:
    print('Key not found - may need re-enrollment');
    break;
    
  default:
    print('Error: ${result.code} - ${result.error}');
}
```

### Re-enrollment (Key Invalidation Recovery)
```dart
// After detecting BiometricError.keyInvalidated
Future<void> reEnrollUser(User user) async {
  // 1. Delete old invalidated keys
  await biometric.deleteKeys();
  
  // 2. Create new keys with same configuration
  final keyResult = await biometric.createKeys(
    keyFormat: KeyFormat.base64,
    promptMessage: 'Re-enroll biometrics',
    config: CreateKeysConfig(
      signatureType: SignatureType.rsa,
      useDeviceCredentials: user.allowDeviceCredentials,
      setInvalidatedByBiometricEnrollment: true,
    ),
  );
  
  if (keyResult.code == BiometricError.success) {
    // 3. Update user's public key in database
    await updateUserPublicKey(user.id, keyResult.publicKey!);
    print('Re-enrollment successful!');
  }
}
```

### Delete Keys
```dart
final deleted = await biometric.deleteKeys();
if (deleted) {
  print('All biometric keys removed');
}
```

## 📝 Notes

- All examples simulate server-side logic locally
- In production, implement proper backend infrastructure
- Follow platform-specific guidelines for production apps
- Consider additional security measures for your use case
- Test on real devices for accurate biometric behavior

## 🤝 Contributing

Found an issue or want to improve an example? Contributions are welcome!

1. Fork the repository
2. Create your feature branch
3. Test your changes on all platforms
4. Submit a pull request

## 📄 License

These examples are part of the biometric_signature plugin and follow the same license.
