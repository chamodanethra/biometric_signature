/// SPKI SHA-256 fingerprints of the Android *software* attestation roots
/// (AOSP `keymaster_soft_attestation_keys.xml`, the EC and RSA "Android
/// Keystore Software Attestation Root" keys, as listed by Google's
/// `android/keyattestation` verifier).
///
/// A chain ending here was produced by a software keystore — typically an
/// emulator or a device without secure hardware. It must never be trusted;
/// the verifier only uses this set to explain the failure.
const Set<String> androidSoftwareRootSpkiSha256 = {
  'd5100c7942ef2e8310dc30ef82729680cf48d690735c3f68179a33c7c370f286',
  'f2c4746f545946c100e72297f8f946344d7052f03a2f694221f9c893b0e6f711',
};
