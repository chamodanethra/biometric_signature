import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/foundation.dart';

/// An account bound to a key on this device. Persisted in the client store
/// (SharedPreferences), which is **not** where the key lives: the two can
/// drift apart (see `reconcile.dart`).
@immutable
class LocalAccount {
  /// Creates an account.
  const LocalAccount({
    required this.alias,
    required this.userId,
    required this.username,
    required this.deviceKeyId,
    required this.trustTier,
    required this.publicKeyFingerprint,
    required this.allowDeviceCredentials,
    required this.invalidateOnEnrollment,
    required this.registeredAt,
    this.lastLoginAt,
    this.lastAuthenticationType,
  });

  /// Restores an account from [toJson].
  factory LocalAccount.fromJson(Map<String, dynamic> json) => LocalAccount(
        alias: json['alias'] as String,
        userId: json['userId'] as String,
        username: json['username'] as String,
        deviceKeyId: json['deviceKeyId'] as String,
        trustTier: TrustTier.values.byName(json['trustTier'] as String),
        publicKeyFingerprint: json['publicKeyFingerprint'] as String,
        allowDeviceCredentials: json['allowDeviceCredentials'] as bool,
        invalidateOnEnrollment: json['invalidateOnEnrollment'] as bool,
        registeredAt: DateTime.parse(json['registeredAt'] as String),
        lastLoginAt: json['lastLoginAt'] == null
            ? null
            : DateTime.parse(json['lastLoginAt'] as String),
        lastAuthenticationType: json['lastAuthenticationType'] == null
            ? null
            : AuthenticationType.values
                .byName(json['lastAuthenticationType'] as String),
      );

  /// The plugin key alias (`acct_…`).
  final String alias;

  /// The server's user id.
  final String userId;

  /// Username.
  final String username;

  /// The server's id for this device key.
  final String deviceKeyId;

  /// Trust tier the server assigned at registration.
  final TrustTier trustTier;

  /// SHA-256 of the registered public key (SPKI), hex.
  final String publicKeyFingerprint;

  /// Created with `useDeviceCredentials: true`; signing passes
  /// `allowDeviceCredentials: true`.
  final bool allowDeviceCredentials;

  /// Created with `setInvalidatedByBiometricEnrollment: true`.
  final bool invalidateOnEnrollment;

  /// When this device was bound.
  final DateTime registeredAt;

  /// Last successful sign-in.
  final DateTime? lastLoginAt;

  /// `authenticationType` reported by the last signature.
  final AuthenticationType? lastAuthenticationType;

  /// Copy after a sign-in.
  LocalAccount signedIn(DateTime at, AuthenticationType? type) => LocalAccount(
        alias: alias,
        userId: userId,
        username: username,
        deviceKeyId: deviceKeyId,
        trustTier: trustTier,
        publicKeyFingerprint: publicKeyFingerprint,
        allowDeviceCredentials: allowDeviceCredentials,
        invalidateOnEnrollment: invalidateOnEnrollment,
        registeredAt: registeredAt,
        lastLoginAt: at,
        lastAuthenticationType: type,
      );

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'alias': alias,
        'userId': userId,
        'username': username,
        'deviceKeyId': deviceKeyId,
        'trustTier': trustTier.name,
        'publicKeyFingerprint': publicKeyFingerprint,
        'allowDeviceCredentials': allowDeviceCredentials,
        'invalidateOnEnrollment': invalidateOnEnrollment,
        'registeredAt': registeredAt.toUtc().toIso8601String(),
        'lastLoginAt': lastLoginAt?.toUtc().toIso8601String(),
        'lastAuthenticationType': lastAuthenticationType?.name,
      };
}

/// Whether an account can sign in from this device.
enum AccountState {
  /// Not checked yet.
  unknown,

  /// Key present and valid, and the server accepts it.
  ready,

  /// No key under the alias (deleted, or preferences restored from a backup
  /// without the keystore).
  keyMissing,

  /// The key was invalidated by a biometric enrollment change.
  keyInvalidated,

  /// A different key sits under the alias.
  keyReplaced,

  /// The server no longer accepts this key (superseded or unbound).
  serverInactive,
}

/// The reconciled state of a [LocalAccount].
@immutable
class AccountStatus {
  /// Creates a status.
  const AccountStatus(this.state, this.message, {this.health});

  /// Not checked yet.
  static const AccountStatus unknown =
      AccountStatus(AccountState.unknown, 'Not checked yet');

  /// State.
  final AccountState state;

  /// Explanation.
  final String message;

  /// The key probe behind it.
  final KeyHealth? health;

  /// Whether the account needs a new key before it can sign in.
  bool get needsRebind =>
      state != AccountState.ready && state != AccountState.unknown;

  /// Short label.
  String get label => switch (state) {
        AccountState.unknown => 'Unchecked',
        AccountState.ready => 'Ready',
        AccountState.keyMissing => 'Key missing',
        AccountState.keyInvalidated => 'Key invalidated',
        AccountState.keyReplaced => 'Different key',
        AccountState.serverInactive => 'Retired by server',
      };
}

/// What kind of key upload is pending.
enum UploadKind {
  /// `/register/finish`.
  register,

  /// `/recovery/finish`.
  recovery,
}

/// A key that was created but whose registration upload did not complete.
///
/// Persisted without the recovery code, so an app restart can at least
/// delete the orphaned key.
@immutable
class PendingUpload {
  /// Creates a pending upload.
  const PendingUpload({
    required this.kind,
    required this.alias,
    required this.username,
    required this.challengeId,
    required this.expiresAt,
    required this.allowDeviceCredentials,
    required this.invalidateOnEnrollment,
    this.recoveryCode,
    this.replacing,
  });

  /// Restores from [toJson] (without the recovery code).
  factory PendingUpload.fromJson(Map<String, dynamic> json) => PendingUpload(
        kind: UploadKind.values.byName(json['kind'] as String),
        alias: json['alias'] as String,
        username: json['username'] as String,
        challengeId: json['challengeId'] as String,
        expiresAt: DateTime.parse(json['expiresAt'] as String),
        allowDeviceCredentials: json['allowDeviceCredentials'] as bool,
        invalidateOnEnrollment: json['invalidateOnEnrollment'] as bool,
        replacing: json['replacing'] as String?,
      );

  /// Registration or recovery.
  final UploadKind kind;

  /// Alias of the created key.
  final String alias;

  /// Username.
  final String username;

  /// The server challenge embedded in the key's attestation.
  final String challengeId;

  /// Until when the server keeps the challenge.
  final DateTime expiresAt;

  /// Key option.
  final bool allowDeviceCredentials;

  /// Key option.
  final bool invalidateOnEnrollment;

  /// The recovery code (memory only).
  final String? recoveryCode;

  /// Alias of the local account this recovery replaces, if any.
  final String? replacing;

  /// JSON form, without [recoveryCode].
  Map<String, dynamic> toJson() => {
        'kind': kind.name,
        'alias': alias,
        'username': username,
        'challengeId': challengeId,
        'expiresAt': expiresAt.toUtc().toIso8601String(),
        'allowDeviceCredentials': allowDeviceCredentials,
        'invalidateOnEnrollment': invalidateOnEnrollment,
        'replacing': replacing,
      };
}

/// The accounts on this device, their reconciled status, and a pending
/// upload, persisted in the client's [KeyValueStore].
class AccountRepository extends ChangeNotifier {
  /// Creates a repository over [store].
  AccountRepository(this.store);

  /// Client storage (`client.` prefix in SharedPreferences).
  final KeyValueStore store;

  static const String _accountsKey = 'accounts';
  static const String _pendingKey = 'pending_upload';

  final List<LocalAccount> _accounts = [];
  final Map<String, AccountStatus> _status = {};
  PendingUpload? _pending;

  /// Accounts, in registration order.
  List<LocalAccount> get accounts => List.unmodifiable(_accounts);

  /// The upload awaiting a retry, if any.
  PendingUpload? get pending => _pending;

  /// The account with [alias].
  LocalAccount? byAlias(String alias) {
    for (final a in _accounts) {
      if (a.alias == alias) return a;
    }
    return null;
  }

  /// The account for [deviceKeyId].
  LocalAccount? byDeviceKeyId(String deviceKeyId) {
    for (final a in _accounts) {
      if (a.deviceKeyId == deviceKeyId) return a;
    }
    return null;
  }

  /// Reconciled status of the account with [alias].
  AccountStatus statusOf(String alias) =>
      _status[alias] ?? AccountStatus.unknown;

  /// Loads persisted state.
  Future<void> load() async {
    final list = await store.readList(_accountsKey) ?? const [];
    _accounts
      ..clear()
      ..addAll([
        for (final a in list) LocalAccount.fromJson(a as Map<String, dynamic>),
      ]);
    final pending = await store.readMap(_pendingKey);
    _pending = pending == null ? null : PendingUpload.fromJson(pending);
    notifyListeners();
  }

  /// Adds or replaces the account with the same alias.
  Future<void> upsert(LocalAccount account, {AccountStatus? status}) async {
    final i = _accounts.indexWhere((a) => a.alias == account.alias);
    if (i < 0) {
      _accounts.add(account);
    } else {
      _accounts[i] = account;
    }
    if (status != null) _status[account.alias] = status;
    await _save();
  }

  /// Removes the account with [alias].
  Future<void> remove(String alias) async {
    _accounts.removeWhere((a) => a.alias == alias);
    _status.remove(alias);
    await _save();
  }

  /// Records a reconciled status.
  void setStatus(String alias, AccountStatus status) {
    _status[alias] = status;
    notifyListeners();
  }

  /// Records a pending upload.
  Future<void> setPending(PendingUpload? pending) async {
    _pending = pending;
    if (pending == null) {
      await store.remove(_pendingKey);
    } else {
      await store.write(_pendingKey, pending.toJson());
    }
    notifyListeners();
  }

  /// Forgets everything on the client side.
  Future<void> clearAll() async {
    _accounts.clear();
    _status.clear();
    _pending = null;
    await store.clear();
    notifyListeners();
  }

  Future<void> _save() async {
    await store.write(_accountsKey, [for (final a in _accounts) a.toJson()]);
    notifyListeners();
  }
}
