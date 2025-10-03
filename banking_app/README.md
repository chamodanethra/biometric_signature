# Banking App Example

A complete banking application example demonstrating secure transaction signing using biometric authentication.

## Features

- 💰 Account balance display
- 💸 Transfer money between accounts
- 🔐 Biometric authentication for transactions
- 📝 Transaction history
- 🔑 Hardware-backed cryptographic signing
- ✅ Transaction verification

## How It Works

1. **Initial Setup**: On first launch, the app generates a key pair using the device's secure hardware (StrongBox/Secure Enclave)
2. **Transaction Creation**: User enters transfer details (amount, recipient)
3. **Biometric Authentication**: User authenticates with fingerprint/face recognition
4. **Signature Generation**: Transaction data is cryptographically signed using the private key
5. **Server Verification**: Signature is sent to server for verification (simulated in this example)
6. **Confirmation**: Transaction is completed and added to history

## Security Features

- Private key never leaves secure hardware
- Each transaction requires fresh biometric authentication
- Transaction data is cryptographically signed
- Server-side signature verification
- Tamper-proof transaction records

## Setup

1. Navigate to the banking_app directory:
```bash
cd banking_app
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
│   ├── account.dart         # Account model
│   └── transaction.dart     # Transaction model
├── services/
│   ├── biometric_service.dart    # Biometric operations
│   └── transaction_service.dart  # Transaction management
├── screens/
│   ├── home_screen.dart     # Main dashboard
│   ├── transfer_screen.dart # Money transfer
│   └── history_screen.dart  # Transaction history
└── widgets/
    ├── account_card.dart    # Account balance card
    └── transaction_tile.dart # Transaction list item
```

## Testing

This example simulates server-side verification. In a real application:
- Send the signature and transaction data to your backend
- Verify the signature using the stored public key
- Only process transactions with valid signatures

## Notes

- This is a demonstration app - not production ready
- Real banking apps require additional security measures
- Server-side verification is simulated locally
- Use proper key management and secure communication (TLS) in production

