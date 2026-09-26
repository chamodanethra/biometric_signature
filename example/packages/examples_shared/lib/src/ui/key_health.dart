import 'package:biometric_signature/biometric_signature.dart';

/// The state of a device key.
enum KeyHealthStatus {
  /// No key under the alias.
  missing,

  /// The key exists but can no longer be used (enrollment change).
  invalidated,

  /// The key exists and is valid (or validity was not reported).
  healthy,
}

/// Result of [probeKey].
class KeyHealth {
  /// Creates a result.
  const KeyHealth({required this.status, required this.info, this.alias});

  /// Status.
  final KeyHealthStatus status;

  /// The raw `getKeyInfo` result.
  final KeyInfo info;

  /// The alias probed (`null` = default alias).
  final String? alias;

  /// Whether the key can be used.
  bool get isHealthy => status == KeyHealthStatus.healthy;

  /// A one-line summary.
  String get summary => switch (status) {
        KeyHealthStatus.missing => 'No key on this device',
        KeyHealthStatus.invalidated =>
          'Key invalidated by a biometric enrollment change',
        KeyHealthStatus.healthy => 'Key present and valid',
      };
}

/// Checks the key under [alias] with `getKeyInfo(checkValidity: true)`.
///
/// Call it on launch and after an unexpected failure, as defence in depth
/// next to the `keyNotFound` / `keyInvalidated` error codes.
Future<KeyHealth> probeKey(BiometricSignature api, {String? alias}) async {
  final info = await api.getKeyInfo(keyAlias: alias, checkValidity: true);
  final KeyHealthStatus status;
  if (info.exists != true) {
    status = KeyHealthStatus.missing;
  } else if (info.isValid == false) {
    status = KeyHealthStatus.invalidated;
  } else {
    status = KeyHealthStatus.healthy;
  }
  return KeyHealth(status: status, info: info, alias: alias);
}
