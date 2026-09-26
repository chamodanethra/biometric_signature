import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';

import '../models/vault_key_record.dart';
import 'provisioning_client.dart';

/// Result of [VaultKeyManager.preflight].
class Preflight {
  /// Creates a result.
  const Preflight({
    required this.platform,
    required this.availability,
    required this.deviceLockSet,
  });

  /// Platform checked.
  final DevicePlatform platform;

  /// `biometricAuthAvailable()`.
  final BiometricAvailability availability;

  /// `isDeviceLockSet()` (Windows: whether Windows Hello is set up).
  final bool deviceLockSet;

  /// The error key creation would most likely return, or `null`.
  BiometricError? get blocker {
    if (!deviceLockSet) {
      return platform == DevicePlatform.windows
          ? BiometricError.notAvailable
          : BiometricError.passcodeNotSet;
    }
    if (availability.hasEnrolledBiometrics == false) {
      return BiometricError.notEnrolled;
    }
    if (availability.canAuthenticate == false) {
      return BiometricError.notAvailable;
    }
    return null;
  }

  /// Enrolled biometric types, e.g. `fingerprint, face`.
  String get biometricsLabel {
    final types = [
      for (final t
          in availability.availableBiometrics ?? const <BiometricType?>[])
        if (t != null && t != BiometricType.unavailable) t.name,
    ];
    return types.isEmpty ? 'none reported' : types.join(', ');
  }
}

/// Owns the vault key (alias `vault`) on this device.
class VaultKeyManager {
  /// Creates a manager.
  const VaultKeyManager({required this.api, required this.platform});

  /// The single alias this app uses. Aliases are limited to `[a-z0-9_-]`.
  static const String alias = 'vault';

  /// The plugin.
  final BiometricSignature api;

  /// The platform (decides the encryption scheme).
  final DevicePlatform platform;

  /// `biometricAuthAvailable()` + `isDeviceLockSet()`.
  Future<Preflight> preflight() async {
    final availability = await api.biometricAuthAvailable();
    final lockSet = await api.isDeviceLockSet();
    return Preflight(
      platform: platform,
      availability: availability,
      deviceLockSet: lockSet,
    );
  }

  /// Creates the vault key. Never replaces an existing one
  /// (`failIfExists: true` returns `keyAlreadyExists` instead).
  Future<KeyCreationResult> create({
    required VaultKeyChoice choice,
    required bool useDeviceCredentials,
  }) {
    return api.createKeys(
      keyAlias: alias,
      keyFormat: KeyFormat.base64,
      promptMessage: 'Create your vault key',
      config: CreateKeysConfig(
        signatureType: choice == VaultKeyChoice.rsa
            ? SignatureType.rsa
            : SignatureType.ecdsa,
        // Android only: EC becomes hybrid (hardware signing key + a software
        // EC decryption key wrapped by a biometric-bound AES key), RSA gets
        // the OAEP decrypt purpose. iOS/macOS keys always decrypt and ignore
        // this flag.
        enableDecryption: true,
        // A new fingerprint or face permanently disables the key: items
        // sealed to it become unreadable (crypto-shredding).
        setInvalidatedByBiometricEnrollment: true,
        useDeviceCredentials: useDeviceCredentials,
        failIfExists: true,
        // Android prompt texts. Hybrid EC creation prompts once, to wrap the
        // decryption key.
        promptSubtitle: 'Secure Vault',
        promptDescription:
            'Confirm to bind the new vault key to your biometrics.',
        cancelButtonText: 'Not now',
      ),
    );
  }

  /// `getKeyInfo` for the vault key.
  Future<KeyInfo> keyInfo({
    KeyFormat format = KeyFormat.base64,
    bool checkValidity = false,
  }) =>
      api.getKeyInfo(
          keyAlias: alias, keyFormat: format, checkValidity: checkValidity);

  /// `getKeyInfo(checkValidity: true)`: missing, invalidated or healthy.
  Future<KeyHealth> probe() => probeKey(api, alias: alias);

  /// `biometricKeyExists(checkValidity: true)`.
  Future<bool> existsAndValid() =>
      api.biometricKeyExists(keyAlias: alias, checkValidity: true);

  /// `deleteKeys` for the vault alias only.
  Future<bool> delete() => api.deleteKeys(keyAlias: alias);

  /// Resolves how to seal items for [key] on this platform.
  EncryptionScheme resolveScheme(KeyMaterial key) => EncryptionTarget.resolve(
        platform: platform,
        algorithm: key.algorithm,
        publicKey: key.publicKey,
        decryptingPublicKey: key.decryptingPublicKey,
        decryptingAlgorithm: key.decryptingAlgorithm,
        isHybridMode: key.isHybridMode,
      );

  /// Key material from a `createKeys` result.
  static KeyMaterial materialFromCreation(KeyCreationResult r) => KeyMaterial(
        algorithm: r.algorithm,
        keySize: r.keySize,
        publicKey: r.publicKey,
        decryptingPublicKey: r.decryptingPublicKey,
        decryptingAlgorithm: r.decryptingAlgorithm,
        isHybridMode: r.isHybridMode,
      );

  /// Key material from a `getKeyInfo` result.
  static KeyMaterial materialFromInfo(KeyInfo i) => KeyMaterial(
        algorithm: i.algorithm,
        keySize: i.keySize,
        publicKey: i.publicKey,
        decryptingPublicKey: i.decryptingPublicKey,
        decryptingAlgorithm: i.decryptingAlgorithm,
        isHybridMode: i.isHybridMode,
      );

  /// What [choice] creates on [platform], before any key exists.
  static String expectedSchemeSummary(
    DevicePlatform platform,
    VaultKeyChoice choice,
  ) {
    switch (platform) {
      case DevicePlatform.android:
        return choice == VaultKeyChoice.ec
            ? 'Hybrid mode: a hardware EC P-256 signing key plus a software '
                'EC P-256 decryption key that is wrapped by a biometric-bound '
                'AES key in the Android keystore. Items are sealed with ECIES '
                'to decryptingPublicKey. Creating it shows one prompt (to '
                'wrap the decryption key).'
            : 'A hardware RSA-2048 keystore key with decryption enabled. '
                'Items are sealed with RSA-OAEP (SHA-256, MGF1-SHA-1) to '
                'publicKey: at most 190 bytes each, so longer items use an '
                'envelope.';
      case DevicePlatform.ios:
      case DevicePlatform.macos:
        return choice == VaultKeyChoice.ec
            ? 'One Secure Enclave P-256 key that signs and decrypts. Items are '
                "sealed with Apple's ECIES (X9.63-SHA256, AES-GCM) to "
                'publicKey. enableDecryption is not needed here.'
            : 'An RSA-2048 key stored wrapped by a Secure Enclave key; it '
                'signs and decrypts. Items are sealed with RSA-OAEP (SHA-256, '
                'MGF1-SHA-256) to publicKey: at most 190 bytes each, so longer '
                'items use an envelope.';
      case DevicePlatform.windows:
        return 'Windows Hello keys cannot decrypt: decrypt() returns '
            'notAvailable, so there is nothing to seal to.';
      case DevicePlatform.other:
        return 'The plugin does not support this platform.';
    }
  }
}
