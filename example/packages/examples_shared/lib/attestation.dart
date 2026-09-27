/// Android key attestation verification for the biometric_signature
/// examples: X.509 parsing, chain validation up to Google's roots, the
/// KeyDescription extension, and a server-style verifier that produces an
/// [AttestationReport].
///
/// Pure Dart (no Flutter). Demo code, not production code: it does not
/// check revocation.
library;

import 'src/attestation/attestation_report.dart';

export 'src/attestation/attestation_report.dart';
export 'src/attestation/attestation_verifier.dart';
export 'src/attestation/chain_validator.dart';
export 'src/attestation/google_roots.dart';
export 'src/attestation/key_description.dart';
export 'src/attestation/software_roots.dart';
export 'src/attestation/x509.dart';
