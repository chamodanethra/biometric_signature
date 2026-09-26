import 'package:examples_shared/server.dart';

import '../models/sealed_item.dart';
import '../models/vault_key_record.dart';
import '../server/provisioning_server.dart';

/// Public key material as returned by `createKeys` or `getKeyInfo`
/// (base64 SPKI strings).
class KeyMaterial {
  /// Creates key material.
  const KeyMaterial({
    required this.algorithm,
    required this.keySize,
    required this.publicKey,
    required this.decryptingPublicKey,
    required this.decryptingAlgorithm,
    required this.isHybridMode,
  });

  /// `algorithm` (`EC` / `RSA`).
  final String? algorithm;

  /// `keySize`.
  final int? keySize;

  /// `publicKey`.
  final String? publicKey;

  /// `decryptingPublicKey` (Android hybrid mode).
  final String? decryptingPublicKey;

  /// `decryptingAlgorithm` (Android hybrid mode).
  final String? decryptingAlgorithm;

  /// `isHybridMode`.
  final bool? isHybridMode;
}

/// The server's answer to a registration.
sealed class RegisterResponse {
  const RegisterResponse();
}

/// Registered.
final class Registered extends RegisterResponse {
  /// Creates the response.
  const Registered({
    required this.generation,
    required this.keyFingerprint,
    required this.schemeLabel,
  });

  /// Registration count for this device.
  final int generation;

  /// Fingerprint of the key the server will seal to.
  final String keyFingerprint;

  /// Scheme the server resolved.
  final String schemeLabel;
}

/// The server refused the key.
final class RegistrationRejected extends RegisterResponse {
  /// Creates the response.
  const RegistrationRejected(this.error, this.reason);

  /// Machine-readable error.
  final String error;

  /// Explanation.
  final String reason;
}

/// Calls the provisioning server over the mock transport.
///
/// Transport failures surface as [TransportException].
class ProvisioningClient {
  /// Creates a client.
  const ProvisioningClient(this.transport);

  /// The "network".
  final MockTransport transport;

  /// Registers the vault key's public half.
  Future<RegisterResponse> register({
    required String deviceId,
    required DevicePlatform platform,
    required VaultKeyChoice choice,
    required KeyMaterial key,
  }) async {
    final response = await transport.call(ProvisioningServer.registerRoute, {
      'deviceId': deviceId,
      'platform': platform.name,
      'keyChoice': choice.name,
      'algorithm': key.algorithm,
      'keySize': key.keySize,
      'publicKey': key.publicKey,
      'decryptingPublicKey': key.decryptingPublicKey,
      'decryptingAlgorithm': key.decryptingAlgorithm,
      'isHybridMode': key.isHybridMode,
    });
    if (response['ok'] != true) {
      return RegistrationRejected(
        response['error'] as String? ?? 'rejected',
        response['reason'] as String? ?? 'The server refused the key.',
      );
    }
    return Registered(
      generation: response['generation'] as int,
      keyFingerprint: response['keyFingerprint'] as String,
      schemeLabel: response['schemeLabel'] as String? ?? '',
    );
  }

  /// Fetches the server's secrets, sealed to the registered key.
  ///
  /// Returns the items, or throws [SyncRejected].
  Future<List<SealedItem>> sync({
    required String deviceId,
    required String keyFingerprint,
  }) async {
    final response = await transport.call(ProvisioningServer.syncRoute, {
      'deviceId': deviceId,
      'keyFingerprint': keyFingerprint,
    });
    if (response['ok'] != true) {
      throw SyncRejected(response['reason'] as String? ?? 'Sync refused.');
    }
    final items = response['items'] as List<dynamic>? ?? const <dynamic>[];
    return [
      for (final e in items)
        SealedItem.fromJson((e as Map).cast<String, dynamic>()),
    ];
  }
}

/// The server refused a sync.
class SyncRejected implements Exception {
  /// Creates the exception.
  const SyncRejected(this.reason);

  /// Explanation.
  final String reason;

  @override
  String toString() => 'SyncRejected: $reason';
}
