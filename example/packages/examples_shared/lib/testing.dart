/// Test helpers for the biometric_signature examples: a software fake of
/// the plugin platform, synthetic attestation chains and a certificate
/// builder.
///
/// Install the fake in widget tests with
/// `BiometricSignaturePlatform.instance = SoftwareBiometricPlatform(...)`.
library;

export 'src/testing/certificate_builder.dart';
export 'src/testing/synthetic_attestation.dart';
export 'src/testing/software_biometric_platform.dart';
