import 'package:examples_shared/crypto.dart';

import 'sealed_item.dart';

/// The two vault key types offered at setup.
enum VaultKeyChoice {
  /// `SignatureType.ecdsa`: Android hybrid ECIES, Apple Secure Enclave ECIES.
  ec('EC (ECIES)'),

  /// `SignatureType.rsa`: RSA-2048 with OAEP.
  rsa('RSA-OAEP');

  const VaultKeyChoice(this.label);

  /// Display name.
  final String label;

  /// The choice matching a key's algorithm string (`EC` / `RSA`).
  static VaultKeyChoice fromAlgorithm(String? algorithm) =>
      (algorithm ?? '').toUpperCase().startsWith('RSA')
          ? VaultKeyChoice.rsa
          : VaultKeyChoice.ec;
}

/// What the device remembers about its registered vault key.
///
/// It mirrors what the provisioning server stored at registration, so the
/// device can seal notes to itself and detect a replaced key.
class VaultKeyRecord {
  /// Creates a record.
  const VaultKeyRecord({
    required this.deviceId,
    required this.platform,
    required this.choice,
    required this.useDeviceCredentials,
    required this.algorithm,
    required this.keySize,
    required this.isHybridMode,
    required this.publicKey,
    required this.decryptingPublicKey,
    required this.scheme,
    required this.generation,
    required this.registeredAt,
  });

  /// Restores a record from [toJson].
  factory VaultKeyRecord.fromJson(Map<String, dynamic> json) => VaultKeyRecord(
        deviceId: json['deviceId'] as String,
        platform: DevicePlatform.fromName(json['platform'] as String?),
        choice: VaultKeyChoice.values.byName(json['choice'] as String),
        useDeviceCredentials: json['useDeviceCredentials'] as bool? ?? false,
        algorithm: json['algorithm'] as String? ?? '',
        keySize: json['keySize'] as int?,
        isHybridMode: json['isHybridMode'] as bool? ?? false,
        publicKey: json['publicKey'] as String?,
        decryptingPublicKey: json['decryptingPublicKey'] as String?,
        scheme: EncryptionScheme.fromJson(
            (json['scheme'] as Map).cast<String, dynamic>()),
        generation: json['generation'] as int? ?? 1,
        registeredAt: DateTime.parse(json['registeredAt'] as String),
      );

  /// This installation's id at the provisioning server.
  final String deviceId;

  /// Platform that created the key.
  final DevicePlatform platform;

  /// EC or RSA.
  final VaultKeyChoice choice;

  /// Whether the key accepts the device PIN / passcode.
  final bool useDeviceCredentials;

  /// `algorithm` from `createKeys` (`EC` / `RSA`).
  final String algorithm;

  /// `keySize` from `createKeys`.
  final int? keySize;

  /// `isHybridMode` from `createKeys` (Android EC with decryption).
  final bool isHybridMode;

  /// Signing public key (base64 SPKI).
  final String? publicKey;

  /// Android hybrid decryption public key (base64 SPKI).
  final String? decryptingPublicKey;

  /// How items are sealed to this key.
  final EncryptionScheme scheme;

  /// Registration count at the server (increments on re-provisioning).
  final int generation;

  /// When the server registered it.
  final DateTime registeredAt;

  /// Fingerprint of the key items are sealed to.
  String get encryptionKeyFingerprint => schemeKeyFingerprint(scheme) ?? '';

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'deviceId': deviceId,
        'platform': platform.name,
        'choice': choice.name,
        'useDeviceCredentials': useDeviceCredentials,
        'algorithm': algorithm,
        'keySize': keySize,
        'isHybridMode': isHybridMode,
        'publicKey': publicKey,
        'decryptingPublicKey': decryptingPublicKey,
        'scheme': scheme.toJson(),
        'generation': generation,
        'registeredAt': registeredAt.toUtc().toIso8601String(),
      };
}
