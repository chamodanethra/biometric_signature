import 'package:flutter/material.dart';

import 'app.dart';
import 'services.dart';

/// Secure Vault: secrets sealed to a hardware-backed key, revealed only by
/// biometric decryption. See README.md for the walkthrough.
void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(SecureVaultApp(services: AppServices.device()));
}
