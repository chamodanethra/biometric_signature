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
**Purpose**: Complete passwordless authentication system

A full-featured passwordless authentication system using biometric signatures instead of passwords.

**Features**:
- 🔐 Passwordless registration and login
- 👤 User account management
- ✅ Challenge-response authentication
- 🔄 Session management
- 🎯 Secure token handling

**Key Concepts**:
- FIDO2/WebAuthn-style authentication
- Challenge-response protocol
- Server-side signature verification
- Public key infrastructure
- Phishing-resistant authentication

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
import 'package:biometric_signature/key_material.dart';

final biometric = BiometricSignature();

// Check availability
final available = await biometric.biometricAuthAvailable();

// Create keys
final keyResult = await biometric.createKeys(
  keyFormat: KeyFormat.pem,
  androidConfig: AndroidConfig(
    useDeviceCredentials: false,
    signatureType: AndroidSignatureType.RSA,
  ),
  iosConfig: IosConfig(
    useDeviceCredentials: false,
    signatureType: IOSSignatureType.RSA,
  ),
);

final pemPublicKey = keyResult?.publicKey.asString();
```

### Sign Data
```dart
final signatureResult = await biometric.createSignature(
  SignatureOptions(
    payload: 'data_to_sign',
    promptMessage: 'Authenticate to continue',
    keyFormat: KeyFormat.raw,
  ),
);

final signatureBase64 = signatureResult?.signature.toBase64();
```

### Error Handling
```dart
try {
  final signatureResult = await biometric.createSignature(options);
  final signatureHex = signatureResult?.signature.toHex();
} on PlatformException catch (e) {
  if (e.code == 'AUTH_FAILED') {
    // Handle authentication failure
  } else if (e.code == 'CANCELLED') {
    // Handle user cancellation
  }
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
3. Test your changes on both platforms
4. Submit a pull request

## 📄 License

These examples are part of the biometric_signature plugin and follow the same license.
