# Document Signer Example

A complete document signing application demonstrating secure document authentication using biometric signatures.

## Features

- 📄 Create and view documents
- ✍️ Sign documents with biometric authentication
- 🔐 Cryptographic proof of document authenticity
- 📋 Document library with signing status
- ✅ Signature verification
- 📤 Export signed documents

## How It Works

1. **Document Creation**: User creates or imports a document
2. **Review**: User reviews the document content
3. **Biometric Signing**: User authenticates with fingerprint/face recognition
4. **Signature Generation**: Document hash is cryptographically signed
5. **Verification**: Signature can be verified using the public key
6. **Export**: Signed document with signature metadata can be exported

## Security Features

- Document integrity verification through hashing
- Hardware-backed cryptographic signing
- Tamper-evident signatures
- Audit trail with timestamps
- Non-repudiation through biometric authentication

## Use Cases

- Legal document signing
- Contract approval
- Medical record authentication
- Compliance documentation
- Secure document workflows

## Setup

1. Navigate to the document_signer directory:
```bash
cd document_signer
```

2. Get dependencies:
```bash
flutter pub get
```

3. Run the app:
```bash
flutter run
```

## Code Structure

```
lib/
├── main.dart                 # App entry point
├── models/
│   ├── document.dart        # Document model
│   └── signature_info.dart  # Signature metadata
├── services/
│   ├── biometric_service.dart    # Biometric operations
│   ├── document_service.dart     # Document management
│   └── signature_service.dart    # Signing operations
├── screens/
│   ├── home_screen.dart     # Document library
│   ├── document_detail_screen.dart  # View & sign document
│   └── create_document_screen.dart  # Create new document
└── widgets/
    ├── document_card.dart   # Document list item
    └── signature_badge.dart # Signature status indicator
```

## Signature Format

Documents are signed using the following process:
1. Document content is hashed using SHA-256
2. Hash is signed with the user's private key
3. Signature metadata includes:
   - Signature value (base64)
   - Timestamp
   - Signer public key
   - Document hash
   - Biometric type used

## Verification

Signatures can be verified by:
1. Recalculating the document hash
2. Verifying the signature using the public key
3. Checking timestamp validity
4. Ensuring document hasn't been modified

## Notes

- This is a demonstration app - not production ready
- Real document signing requires additional legal considerations
- Consider using standardized formats (PDF signing, XAdES, etc.) in production
- Implement proper key management and certificate chains for enterprise use

