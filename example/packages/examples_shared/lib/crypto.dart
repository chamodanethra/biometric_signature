/// Encoding and crypto helpers for the biometric_signature examples.
///
/// Pure Dart (no Flutter): public-key normalization, DER, canonical JSON,
/// signature verification, RSA-OAEP, ECIES and envelope encryption matching
/// what each platform's `decrypt()` expects.
///
/// Demo code, not production code.
library;

export 'src/crypto/aes_gcm.dart';
export 'src/crypto/ecies.dart';
export 'src/crypto/encryption_target.dart';
export 'src/crypto/envelope.dart';
export 'src/crypto/hash.dart';
export 'src/crypto/oaep.dart';
export 'src/crypto/public_key.dart';
export 'src/crypto/signature_verifier.dart';
export 'src/crypto/software_keys.dart';
export 'src/encoding/bytes.dart';
export 'src/encoding/canonical_json.dart';
export 'src/encoding/der.dart';
export 'src/encoding/pem.dart';
export 'src/platform/device_platform.dart';
