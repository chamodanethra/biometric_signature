/// The platforms the plugin supports, plus [other] for everything else.
///
/// Pure Dart so server-side helpers can use it. Use
/// `currentDevicePlatform()` from `ui.dart` to get the running platform.
enum DevicePlatform {
  /// Android (AndroidKeyStore, TEE / StrongBox).
  android('Android'),

  /// iOS (Secure Enclave).
  ios('iOS'),

  /// macOS (Secure Enclave).
  macos('macOS'),

  /// Windows (Windows Hello).
  windows('Windows'),

  /// Any platform the plugin does not support (web, Linux, Fuchsia).
  other('Other');

  const DevicePlatform(this.label);

  /// Display name.
  final String label;

  /// Whether this is iOS or macOS.
  bool get isApple => this == ios || this == macos;

  /// Parses [name] (e.g. from JSON); unknown values map to [other].
  static DevicePlatform fromName(String? name) {
    for (final p in values) {
      if (p.name == name) return p;
    }
    return other;
  }
}

/// How trustworthy `authenticationType` is on a platform.
enum AuthTypeReliability {
  /// Reported by the OS (Android `BiometricPrompt` result).
  authoritative,

  /// Inferred by the plugin from the prompt policy (iOS/macOS).
  inferred,

  /// Never reported; always `unknown` (Windows Hello).
  notReported,
}

/// What the plugin can do on a platform. Mirrors the plugin's native code,
/// not just its README.
class PlatformCapabilities {
  const PlatformCapabilities._({
    required this.platform,
    required this.supportsEcKeys,
    required this.supportsDecrypt,
    required this.supportsAttestation,
    required this.silentKeysPrompt,
    required this.supportsEnrollmentInvalidation,
    required this.authTypeReliability,
    required this.notes,
  });

  /// Capabilities for [platform].
  static PlatformCapabilities of(DevicePlatform platform) => switch (platform) {
        DevicePlatform.android => const PlatformCapabilities._(
            platform: DevicePlatform.android,
            supportsEcKeys: true,
            supportsDecrypt: true,
            supportsAttestation: true,
            silentKeysPrompt: false,
            supportsEnrollmentInvalidation: true,
            authTypeReliability: AuthTypeReliability.authoritative,
            notes: [
              'Keys live in the TEE or StrongBox; hardware key attestation '
                  'is available with attestationChallenge.',
              'EC decryption needs enableDecryption (hybrid mode: a '
                  'separate software EC key wrapped by a keystore AES key).',
              'RSA decryption is OAEP with SHA-256 and MGF1-SHA-1.',
            ],
          ),
        DevicePlatform.ios || DevicePlatform.macos => PlatformCapabilities._(
            platform: platform,
            supportsEcKeys: true,
            supportsDecrypt: true,
            supportsAttestation: false,
            silentKeysPrompt: false,
            supportsEnrollmentInvalidation: true,
            authTypeReliability: AuthTypeReliability.inferred,
            notes: const [
              'EC keys live in the Secure Enclave and decrypt with Apple '
                  'ECIES (X9.63-SHA256, AES-GCM).',
              'RSA keys are software keys wrapped by a Secure Enclave key; '
                  'decryption is OAEP with SHA-256 and MGF1-SHA-256.',
              'No per-key attestation: attestationChallenge returns '
                  'notSupported.',
              'authenticationType is inferred from the prompt policy.',
            ],
          ),
        DevicePlatform.windows => const PlatformCapabilities._(
            platform: DevicePlatform.windows,
            supportsEcKeys: false,
            supportsDecrypt: false,
            supportsAttestation: false,
            silentKeysPrompt: true,
            supportsEnrollmentInvalidation: false,
            authTypeReliability: AuthTypeReliability.notReported,
            notes: [
              'Windows Hello keys are RSA-2048 only; signatureType is '
                  'ignored.',
              'decrypt() returns notAvailable.',
              'Every signature prompts, even for requireAuthentication: '
                  'false keys.',
              'authenticationType is always unknown.',
            ],
          ),
        DevicePlatform.other => const PlatformCapabilities._(
            platform: DevicePlatform.other,
            supportsEcKeys: false,
            supportsDecrypt: false,
            supportsAttestation: false,
            silentKeysPrompt: false,
            supportsEnrollmentInvalidation: false,
            authTypeReliability: AuthTypeReliability.notReported,
            notes: ['The plugin does not support this platform.'],
          ),
      };

  /// The platform described.
  final DevicePlatform platform;

  /// EC P-256 keys (`SignatureType.ecdsa`). Windows is RSA only.
  final bool supportsEcKeys;

  /// `decrypt()` works (Android, iOS, macOS).
  final bool supportsDecrypt;

  /// Hardware key attestation via `attestationChallenge` (Android only).
  final bool supportsAttestation;

  /// Whether `requireAuthentication: false` keys still show a prompt
  /// (Windows Hello always prompts).
  final bool silentKeysPrompt;

  /// Whether keys can be invalidated by a biometric enrollment change.
  final bool supportsEnrollmentInvalidation;

  /// How much `authenticationType` can be trusted.
  final AuthTypeReliability authTypeReliability;

  /// Short human-readable notes.
  final List<String> notes;

  /// Whether silent (non-interactive) keys really are silent.
  bool get supportsSilentKeys =>
      platform != DevicePlatform.other && !silentKeysPrompt;
}
