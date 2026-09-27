import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/foundation.dart';

import '../models/sealed_item.dart';
import '../models/vault_key_record.dart';
import '../services.dart';
import 'provisioning_client.dart';
import 'reveal_service.dart';
import 'sharing.dart';
import 'vault_key_manager.dart';
import 'vault_repository.dart';

/// Which top-level screen to show.
enum VaultPhase {
  /// Starting up.
  loading,

  /// No registered vault key: show setup.
  setup,

  /// A vault key is registered: show the vault.
  ready,
}

/// The registered vault key's state on this device.
enum VaultKeyState {
  /// Present and valid.
  healthy,

  /// Invalidated by a biometric enrollment change.
  invalidated,

  /// Gone (deleted, or not restored with a backup).
  missing,

  /// A different key than the registered one is under the alias.
  replaced,
}

/// Whether an item can still be opened.
enum ItemAccess {
  /// Sealed to the current, healthy key.
  readable,

  /// A server item that cannot be opened now; the server can seal a fresh
  /// copy after re-provisioning (and a sync).
  awaitingReseal,

  /// A device note or shared item sealed to a key that can never be used
  /// again. Nothing can decrypt it: it is crypto-shredded.
  lost,
}

/// Result of [VaultController.provision] and friends.
sealed class ProvisionOutcome {
  const ProvisionOutcome();
}

/// Key created (or reused), registered and synced.
final class Provisioned extends ProvisionOutcome {
  /// Creates the outcome.
  const Provisioned({
    required this.scheme,
    required this.generation,
    required this.itemsReceived,
    this.syncError,
  });

  /// The scheme the server seals with.
  final EncryptionScheme scheme;

  /// Registration count at the server.
  final int generation;

  /// Server items received.
  final int itemsReceived;

  /// Why the first sync failed, if it did (registration still succeeded).
  final String? syncError;
}

/// `createKeys` (or reading the existing key) failed.
final class KeyCreationFailed extends ProvisionOutcome {
  /// Creates the outcome.
  const KeyCreationFailed(this.code, this.message);

  /// Plugin error code; `keyAlreadyExists` means a key is already there.
  final BiometricError code;

  /// Plugin message.
  final String? message;
}

/// The key exists on the device but the server did not register it.
final class RegistrationFailed extends ProvisionOutcome {
  /// Creates the outcome.
  const RegistrationFailed(this.message, {required this.rejected});

  /// What went wrong.
  final String message;

  /// `true` if the server refused the key; `false` for a network failure
  /// (retrying is safe: the key is re-read with `getKeyInfo`).
  final bool rejected;
}

/// Result of [VaultController.syncServerItems].
class SyncOutcome {
  /// Creates the outcome.
  const SyncOutcome(this.received, [this.error]);

  /// Items received.
  final int received;

  /// Why it failed.
  final String? error;

  /// Whether it succeeded.
  bool get ok => error == null;
}

/// App state and use cases: setup, provisioning, sealing, revealing,
/// re-provisioning, sharing and reset.
class VaultController extends ChangeNotifier {
  /// Creates the controller. Call [start] once.
  VaultController(this.services)
      : keys = VaultKeyManager(api: services.api, platform: services.platform),
        reveals = RevealService(services.api) {
    services.repository.addListener(notifyListeners);
  }

  /// Wiring.
  final AppServices services;

  /// The vault key.
  final VaultKeyManager keys;

  /// The cryptographic gate.
  final RevealService reveals;

  VaultPhase _phase = VaultPhase.loading;
  VaultKeyState _keyState = VaultKeyState.healthy;
  bool _existingKeyOnDevice = false;
  bool _titlesUnlocked = false;
  String? _busy;
  bool _disposed = false;

  /// Device storage.
  VaultRepository get repo => services.repository;

  /// This platform.
  DevicePlatform get platform => services.platform;

  /// What the plugin can do here.
  PlatformCapabilities get capabilities => PlatformCapabilities.of(platform);

  /// Which screen to show.
  VaultPhase get phase => _phase;

  /// The vault key's state.
  VaultKeyState get keyState => _keyState;

  /// Whether a key already exists under the `vault` alias (e.g. the iOS
  /// keychain kept it across a reinstall).
  bool get existingKeyOnDevice => _existingKeyOnDevice;

  /// The registered key.
  VaultKeyRecord? get record => repo.keyRecord;

  /// A description of the running operation, or `null`.
  String? get busy => _busy;

  /// Whether item titles may be shown (the UI gate).
  bool get titlesVisible => !repo.hideTitles || _titlesUnlocked;

  /// A label identifying this vault to people you share with.
  String get senderLabel => '${platform.label} vault ${repo.deviceId}';

  /// Starts the server, loads storage and reconciles with the key.
  Future<void> start() async {
    await services.start();
    await reconcile();
  }

  /// Compares the stored registration with `getKeyInfo(checkValidity:
  /// true)`. Keys can outlive app data (the iOS keychain survives an
  /// uninstall) and app data can outlive keys (Android Auto Backup restores
  /// preferences but never keystore keys).
  Future<void> reconcile() async {
    if (!capabilities.supportsDecrypt) {
      _phase = VaultPhase.setup;
      _notify();
      return;
    }
    final health = await keys.probe();
    _existingKeyOnDevice = health.status != KeyHealthStatus.missing;
    final record = repo.keyRecord;
    if (record == null) {
      _phase = VaultPhase.setup;
    } else {
      _keyState = _stateFor(health, record);
      _phase = VaultPhase.ready;
    }
    _notify();
  }

  /// Re-checks the key and updates [keyState].
  Future<KeyHealth> refreshKeyHealth() async {
    final health = await keys.probe();
    _existingKeyOnDevice = health.status != KeyHealthStatus.missing;
    final record = repo.keyRecord;
    if (record != null) _keyState = _stateFor(health, record);
    _notify();
    return health;
  }

  VaultKeyState _stateFor(KeyHealth health, VaultKeyRecord record) {
    switch (health.status) {
      case KeyHealthStatus.missing:
        return VaultKeyState.missing;
      case KeyHealthStatus.invalidated:
        return VaultKeyState.invalidated;
      case KeyHealthStatus.healthy:
        final scheme =
            keys.resolveScheme(VaultKeyManager.materialFromInfo(health.info));
        final fingerprint = schemeKeyFingerprint(scheme);
        // A null fingerprint means getKeyInfo returned no public key (an
        // iOS RSA key from before plugin 13.1.0, until its first use).
        if (fingerprint != null &&
            fingerprint != record.encryptionKeyFingerprint) {
          return VaultKeyState.replaced;
        }
        return VaultKeyState.healthy;
    }
  }

  /// `biometricAuthAvailable` + `isDeviceLockSet`.
  Future<Preflight> preflight() => keys.preflight();

  /// Creates the vault key, registers it and fetches the server's items.
  Future<ProvisionOutcome> provision({
    required VaultKeyChoice choice,
    required bool useDeviceCredentials,
  }) async {
    _setBusy('Creating the vault key…');
    try {
      final created = await keys.create(
        choice: choice,
        useDeviceCredentials: useDeviceCredentials,
      );
      if (created.code != BiometricError.success) {
        final code = created.code ?? BiometricError.unknown;
        if (code == BiometricError.keyAlreadyExists) {
          _existingKeyOnDevice = true;
        }
        return KeyCreationFailed(code, created.error);
      }
      _existingKeyOnDevice = true;
      return await _register(
        VaultKeyManager.materialFromCreation(created),
        choice: choice,
        useDeviceCredentials: useDeviceCredentials,
      );
    } finally {
      _setBusy(null);
    }
  }

  /// Registers the key already under the alias (after `keyAlreadyExists`,
  /// or to retry a failed registration). Reads it with `getKeyInfo`.
  ///
  /// The plugin cannot report whether an existing key accepts the device
  /// credential, so [useDeviceCredentials] is taken on trust.
  Future<ProvisionOutcome> registerExistingKey({
    required bool useDeviceCredentials,
  }) async {
    _setBusy('Reading the existing key…');
    try {
      final health = await keys.probe();
      switch (health.status) {
        case KeyHealthStatus.missing:
          _existingKeyOnDevice = false;
          return const KeyCreationFailed(BiometricError.keyNotFound,
              'There is no vault key on this device.');
        case KeyHealthStatus.invalidated:
          return const KeyCreationFailed(
              BiometricError.keyInvalidated,
              'The existing vault key was invalidated by a biometric '
              'enrollment change. Replace it.');
        case KeyHealthStatus.healthy:
          break;
      }
      final material = VaultKeyManager.materialFromInfo(health.info);
      return await _register(
        material,
        choice: VaultKeyChoice.fromAlgorithm(material.algorithm),
        useDeviceCredentials: useDeviceCredentials,
      );
    } finally {
      _setBusy(null);
    }
  }

  /// Deletes the key under the alias and provisions a new one.
  Future<ProvisionOutcome> replaceExistingKey({
    required VaultKeyChoice choice,
    required bool useDeviceCredentials,
  }) async {
    _setBusy('Deleting the existing key…');
    await keys.delete();
    _existingKeyOnDevice = false;
    return provision(
        choice: choice, useDeviceCredentials: useDeviceCredentials);
  }

  /// After invalidation (or loss): deletes the old key, creates a new one
  /// with the same settings, registers it and lets the server re-seal its
  /// secrets. Device notes sealed to the old key stay lost.
  Future<ProvisionOutcome> reprovision() async {
    final record = repo.keyRecord;
    _setBusy('Deleting the old vault key…');
    await keys.delete();
    _existingKeyOnDevice = false;
    if (record != null) _keyState = VaultKeyState.missing;
    final outcome = await provision(
      choice: record?.choice ?? VaultKeyChoice.ec,
      useDeviceCredentials: record?.useDeviceCredentials ?? false,
    );
    // If creation or registration failed, report what is on the device
    // now: nothing (missing) or an unregistered new key (replaced).
    if (outcome is! Provisioned) await refreshKeyHealth();
    return outcome;
  }

  Future<ProvisionOutcome> _register(
    KeyMaterial material, {
    required VaultKeyChoice choice,
    required bool useDeviceCredentials,
  }) async {
    _setBusy('Registering with the provisioning server…');
    final scheme = keys.resolveScheme(material);
    final RegisterResponse response;
    try {
      response = await services.client.register(
        deviceId: repo.deviceId,
        platform: platform,
        choice: choice,
        key: material,
      );
    } on TransportException catch (e) {
      return RegistrationFailed(e.message, rejected: false);
    }
    final Registered registered;
    switch (response) {
      case RegistrationRejected(:final reason):
        return RegistrationFailed(reason, rejected: true);
      case final Registered r:
        registered = r;
    }
    final mine = schemeKeyFingerprint(scheme);
    if (registered.keyFingerprint != mine) {
      return RegistrationFailed(
        'The server registered key '
        '${shortFingerprint(registered.keyFingerprint)}, but this device '
        'holds ${shortFingerprint(mine ?? '')}. Registration must be '
        'authenticated end to end.',
        rejected: true,
      );
    }
    await repo.saveKeyRecord(VaultKeyRecord(
      deviceId: repo.deviceId,
      platform: platform,
      choice: choice,
      useDeviceCredentials: useDeviceCredentials,
      algorithm: material.algorithm ?? '',
      keySize: material.keySize,
      isHybridMode: material.isHybridMode ?? false,
      publicKey: material.publicKey,
      decryptingPublicKey: material.decryptingPublicKey,
      scheme: scheme,
      generation: registered.generation,
      registeredAt: DateTime.now().toUtc(),
    ));
    _keyState = VaultKeyState.healthy;
    _existingKeyOnDevice = true;
    _titlesUnlocked = false;
    _phase = VaultPhase.ready;
    _notify();
    _setBusy('Receiving sealed secrets…');
    final sync = await syncServerItems();
    return Provisioned(
      scheme: scheme,
      generation: registered.generation,
      itemsReceived: sync.received,
      syncError: sync.error,
    );
  }

  /// Fetches the server's secrets, freshly sealed to the registered key,
  /// replacing older server copies.
  Future<SyncOutcome> syncServerItems() async {
    final record = repo.keyRecord;
    if (record == null) return const SyncOutcome(0, 'Set up the vault first.');
    try {
      final items = await services.client.sync(
        deviceId: record.deviceId,
        keyFingerprint: record.encryptionKeyFingerprint,
      );
      await repo.replaceServerItems(items);
      return SyncOutcome(items.length);
    } on TransportException catch (e) {
      return SyncOutcome(0, e.message);
    } on SyncRejected catch (e) {
      return SyncOutcome(0, e.reason);
    } on FormatException catch (e) {
      return SyncOutcome(0, 'Malformed delivery: ${e.message}');
    }
  }

  /// Seals a note to the vault's own public key. No prompt and no private
  /// key: the vault is write-only until you authenticate.
  Future<SealedItem> addNote({
    required String title,
    required String body,
  }) async {
    final record = repo.keyRecord;
    if (record == null || _keyState != VaultKeyState.healthy) {
      throw StateError('The vault key is not usable; re-provision first.');
    }
    final trimmed = title.trim();
    final item = SealedItem.seal(
      id: 'note-${toHex(secureRandomBytes(6))}',
      title: trimmed.isEmpty ? 'Untitled note' : trimmed,
      origin: ItemOrigin.device,
      scheme: record.scheme,
      plaintext: body,
      createdAt: DateTime.now().toUtc(),
    );
    await repo.add(item);
    return item;
  }

  /// Decrypts [item] with the plugin (prompts). Updates [keyState] when the
  /// key turns out to be invalidated or missing.
  Future<RevealOutcome> reveal(
    SealedItem item, {
    PayloadFormat format = PayloadFormat.base64,
  }) async {
    final outcome = await reveals.reveal(
      item,
      format: format,
      allowDeviceCredentials: record?.useDeviceCredentials ?? false,
      promptTitle: titlesVisible ? item.title : null,
    );
    if (outcome is RevealFailed) {
      if (outcome.code == BiometricError.keyInvalidated ||
          outcome.health?.status == KeyHealthStatus.invalidated) {
        _setKeyState(VaultKeyState.invalidated);
      } else if (outcome.code == BiometricError.keyNotFound ||
          outcome.health?.status == KeyHealthStatus.missing) {
        _setKeyState(VaultKeyState.missing);
      }
    }
    return outcome;
  }

  /// Whether [item] can still be opened.
  ItemAccess accessFor(SealedItem item) {
    final record = repo.keyRecord;
    final sealedToCurrent =
        record != null && item.recipientKey == record.encryptionKeyFingerprint;
    if (sealedToCurrent && _keyState == VaultKeyState.healthy) {
      return ItemAccess.readable;
    }
    return item.origin == ItemOrigin.server
        ? ItemAccess.awaitingReseal
        : ItemAccess.lost;
  }

  /// Items that can never be opened again.
  List<SealedItem> get lostItems => [
        for (final i in repo.items)
          if (accessFor(i) == ItemAccess.lost) i,
      ];

  /// Deletes [lostItems]; returns how many.
  Future<int> deleteLostItems() =>
      repo.removeWhere((i) => accessFor(i) == ItemAccess.lost);

  /// Deletes one item.
  Future<void> deleteItem(String id) => repo.remove(id);

  /// Turns the "hide titles" UI gate on or off.
  Future<void> setHideTitles(bool value) async {
    if (value) _titlesUnlocked = false;
    await repo.setHideTitles(value);
  }

  /// Shows titles after a `simplePrompt`. A UI gate only: titles are stored
  /// unencrypted and nothing is decrypted here.
  Future<SimplePromptResult> unlockTitles() async {
    final result = await services.api.simplePrompt(
      promptMessage: 'Show vault item titles',
      config: SimplePromptConfig(
        subtitle: 'UI gate only: nothing is decrypted',
        description: 'Titles are stored unencrypted. This check only decides '
            'whether the app shows them.',
        cancelButtonText: 'Cancel',
        allowDeviceCredentials: record?.useDeviceCredentials ?? false,
        biometricStrength: BiometricStrength.strong,
      ),
    );
    if (result.success == true) {
      _titlesUnlocked = true;
      _notify();
    }
    return result;
  }

  /// Hides titles again (on app pause).
  void lockTitles() {
    if (!_titlesUnlocked) return;
    _titlesUnlocked = false;
    _notify();
  }

  /// This vault's shareable address (from `getKeyInfo` with
  /// `KeyFormat.pem`).
  Future<VaultAddress> myAddress() {
    final record = repo.keyRecord;
    if (record == null) {
      throw const SharingException('Set up your vault first.');
    }
    return buildVaultAddress(
      api: services.api,
      platform: platform,
      record: record,
      label: senderLabel,
    );
  }

  /// Stores a sealed item someone sent to this vault.
  Future<SealedItem> importShared(String text) async {
    final record = repo.keyRecord;
    if (record == null) {
      throw const SharingException('Set up your vault first.');
    }
    final item = parseSealedItem(text,
        myKeyFingerprint: record.encryptionKeyFingerprint);
    await repo.add(item);
    return item;
  }

  /// `deleteAllKeys()` and clears both the device's and the server's data.
  Future<void> resetDemo() async {
    _setBusy('Resetting the demo…');
    try {
      await services.api.deleteAllKeys();
      await services.resetStores();
      _keyState = VaultKeyState.healthy;
      _existingKeyOnDevice = false;
      _titlesUnlocked = false;
      _phase = VaultPhase.setup;
    } finally {
      _setBusy(null);
    }
  }

  void _setKeyState(VaultKeyState state) {
    if (_keyState == state) return;
    _keyState = state;
    _notify();
  }

  void _setBusy(String? label) {
    _busy = label;
    _notify();
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    services.repository.removeListener(notifyListeners);
    super.dispose();
  }
}
