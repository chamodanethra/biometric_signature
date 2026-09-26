import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/ui.dart';

import '../server/models.dart';
import 'accounts.dart';

/// Checks one account against the key on this device and the server's
/// record of it.
///
/// Local account records and keys can drift apart:
/// - Android Auto Backup restores SharedPreferences onto a new phone, but
///   never keystore keys → the key is **missing**.
/// - Enrolling a new fingerprint or face permanently invalidates keys
///   created with `setInvalidatedByBiometricEnrollment: true` → the key is
///   **invalidated** (`getKeyInfo(checkValidity: true)` reports
///   `isValid: false`).
/// - A recovery elsewhere supersedes this key, or it was unbound → the
///   server no longer accepts it.
/// - The reverse also happens: iOS keychain keys survive an uninstall while
///   preferences do not. "Sign in to an existing account" finds such keys
///   through the aliases the server lists for the username.
Future<AccountStatus> reconcileAccount({
  required BiometricSignature api,
  required MockTransport transport,
  required LocalAccount account,
}) async {
  final health = await probeKey(api, alias: account.alias);
  switch (health.status) {
    case KeyHealthStatus.missing:
      return AccountStatus(
        AccountState.keyMissing,
        'There is no key under ${account.alias} on this device: it was '
        'deleted, or the app data was restored from a backup that cannot '
        'include hardware keys. Re-bind with your recovery code.',
        health: health,
      );
    case KeyHealthStatus.invalidated:
      return AccountStatus(
        AccountState.keyInvalidated,
        'A fingerprint or face was added or removed, so this key was '
        'permanently invalidated. Re-bind with your recovery code.',
        health: health,
      );
    case KeyHealthStatus.healthy:
      break;
  }
  final publicKey = health.info.publicKey;
  if (publicKey != null) {
    try {
      if (ParsedPublicKey.parse(publicKey).fingerprint !=
          account.publicKeyFingerprint) {
        return AccountStatus(
          AccountState.keyReplaced,
          'The key under ${account.alias} is not the one registered for '
          'this account. Re-bind with your recovery code.',
          health: health,
        );
      }
    } on FormatException {
      // Unparseable key info: let the server check below decide.
    }
  }
  try {
    final response = await transport.call(ApiRoutes.deviceStatus, {
      'userId': account.userId,
      'deviceKeyId': account.deviceKeyId,
    });
    if (response['ok'] != true) {
      return AccountStatus(
        AccountState.serverInactive,
        'The server does not know this key: ${response['reason']}',
        health: health,
      );
    }
    final device =
        DeviceKeyRecord.fromJson(response['device'] as Map<String, dynamic>);
    if (!device.isActive) {
      return AccountStatus(
        AccountState.serverInactive,
        device.status == DeviceKeyStatus.superseded
            ? 'The server replaced this key with ${device.supersededBy}, '
                'bound with the recovery code.'
            : 'This key was unbound from the account.',
        health: health,
      );
    }
  } on TransportException catch (e) {
    return AccountStatus(
      AccountState.ready,
      'The key is healthy; the server could not be reached (${e.message}).',
      health: health,
    );
  }
  return AccountStatus(
    AccountState.ready,
    'Key present and valid, and the server accepts it.',
    health: health,
  );
}

/// Reconciles every account, and deletes the key of a registration whose
/// upload can no longer be retried (challenge expired, or a recovery whose
/// code was not kept across an app restart).
Future<void> reconcileAll({
  required BiometricSignature api,
  required MockTransport transport,
  required AccountRepository accounts,
  DateTime? now,
}) async {
  final pending = accounts.pending;
  if (pending != null) {
    final expired =
        !(now ?? DateTime.now().toUtc()).isBefore(pending.expiresAt);
    final unusable =
        pending.kind == UploadKind.recovery && pending.recoveryCode == null;
    if (expired || unusable) {
      await api.deleteKeys(keyAlias: pending.alias);
      await accounts.setPending(null);
    }
  }
  for (final account in accounts.accounts) {
    accounts.setStatus(
      account.alias,
      await reconcileAccount(api: api, transport: transport, account: account),
    );
  }
}
