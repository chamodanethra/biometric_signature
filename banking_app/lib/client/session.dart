/// The app's client-side state: the binding, key health and the last
/// account snapshot.
library;

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/foundation.dart';

import '../server/models.dart';
import 'bank_client.dart';
import 'key_setup.dart';

/// What the app remembers about its binding (client store).
class ClientEnrollment {
  /// Creates a record.
  const ClientEnrollment({
    required this.deviceId,
    required this.customerName,
    required this.allowDeviceCredential,
    required this.deviceKeyFingerprint,
    required this.approvalKeyFingerprint,
    required this.enrolledAt,
  });

  /// Restores a record from [toJson].
  factory ClientEnrollment.fromJson(Map<String, dynamic> json) =>
      ClientEnrollment(
        deviceId: json['deviceId'] as String,
        customerName: json['customerName'] as String,
        allowDeviceCredential: json['allowDeviceCredential'] as bool,
        deviceKeyFingerprint: json['deviceKeyFingerprint'] as String,
        approvalKeyFingerprint: json['approvalKeyFingerprint'] as String,
        enrolledAt: DateTime.parse(json['enrolledAt'] as String),
      );

  /// Bank-assigned device id.
  final String deviceId;

  /// Customer name.
  final String customerName;

  /// Whether the approval key accepts the device PIN / passcode.
  final bool allowDeviceCredential;

  /// Registered `device_binding` fingerprint.
  final String deviceKeyFingerprint;

  /// Registered `txn_approval` fingerprint.
  final String approvalKeyFingerprint;

  /// When the device was bound.
  final DateTime enrolledAt;

  /// Copy after an approval-key rotation.
  ClientEnrollment withApprovalKey(String fingerprint,
          {required bool allowDeviceCredential}) =>
      ClientEnrollment(
        deviceId: deviceId,
        customerName: customerName,
        allowDeviceCredential: allowDeviceCredential,
        deviceKeyFingerprint: deviceKeyFingerprint,
        approvalKeyFingerprint: fingerprint,
        enrolledAt: enrolledAt,
      );

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'deviceId': deviceId,
        'customerName': customerName,
        'allowDeviceCredential': allowDeviceCredential,
        'deviceKeyFingerprint': deviceKeyFingerprint,
        'approvalKeyFingerprint': approvalKeyFingerprint,
        'enrolledAt': enrolledAt.toUtc().toIso8601String(),
      };
}

/// Client-side state, shared by every screen.
class BankSession extends ChangeNotifier {
  /// Creates the session.
  BankSession({
    required this.api,
    required this.client,
    required this.store,
    required this.platform,
  });

  /// The plugin.
  final BiometricSignature api;

  /// Bank client.
  final BankClient client;

  /// Client persistence (`client.` prefix).
  final KeyValueStore store;

  /// The platform.
  final DevicePlatform platform;

  bool _ready = false;
  ClientEnrollment? _enrollment;
  AccountsSnapshot? _snapshot;
  String? _approvalsLockedReason;
  String? _bindingLostReason;
  String? _previousDeviceId;
  bool _refreshing = false;

  /// Startup finished.
  bool get ready => _ready;

  /// The binding, if the device is bound.
  ClientEnrollment? get enrollment => _enrollment;

  /// Whether the device is bound.
  bool get isEnrolled => _enrollment != null;

  /// The last `/accounts` response.
  AccountsSnapshot? get snapshot => _snapshot;

  /// Why approvals (tiers B and C) are locked, if they are.
  String? get approvalsLockedReason => _approvalsLockedReason;

  /// Whether the approval key is unusable.
  bool get approvalsLocked => _approvalsLockedReason != null;

  /// Why the device must be bound again, if it must.
  String? get bindingLostReason => _bindingLostReason;

  /// The binding a new enrollment replaces.
  String? get previousDeviceId => _previousDeviceId;

  /// A request to `/accounts` is in flight.
  bool get refreshing => _refreshing;

  /// The last refresh error.
  BankError? refreshError;

  /// Startup error, if any.
  Object? startupError;

  /// `device_binding` health from the last probe.
  KeyHealth? deviceKeyHealth;

  /// `txn_approval` health from the last probe.
  KeyHealth? approvalKeyHealth;

  /// The last key registration (onboarding or rotation), shown once.
  KeyRegistrationResult? lastRegistration;

  /// Windows Hello prompts even for the silent key: no background refresh.
  bool get silentKeysPrompt =>
      PlatformCapabilities.of(platform).silentKeysPrompt;

  /// Loads the binding and reconciles it with the keys on the device and
  /// the bank's records. iOS keychain items survive an uninstall and Android
  /// Auto Backup can restore preferences without keys, so neither side is
  /// assumed to be in sync.
  Future<void> bootstrap() async {
    try {
      final json = await store.readMap('enrollment');
      if (json != null) {
        _enrollment = ClientEnrollment.fromJson(json);
        client.deviceId = _enrollment!.deviceId;
        await _reconcileKeys();
        if (isEnrolled && !silentKeysPrompt) await refresh();
      }
    } catch (e) {
      startupError = e;
    }
    _ready = true;
    notifyListeners();
  }

  Future<void> _reconcileKeys() async {
    final enrollment = _enrollment;
    if (enrollment == null) return;
    final device = await probeKey(api, alias: KeyAliases.deviceBinding);
    deviceKeyHealth = device;
    if (device.status != KeyHealthStatus.healthy) {
      await _loseBinding('The device-binding key is missing on this device '
          '(${device.summary.toLowerCase()}), so the app can no longer '
          'prove to the bank that it is the bound device.');
      return;
    }
    if (_fingerprint(device.info.publicKey) case final fp?
        when fp != enrollment.deviceKeyFingerprint) {
      await _loseBinding('The device-binding key on this device is not the '
          'one the bank registered.');
      return;
    }
    final approval = await probeKey(api, alias: KeyAliases.approval);
    approvalKeyHealth = approval;
    switch (approval.status) {
      case KeyHealthStatus.missing:
        _approvalsLockedReason = 'Your approval key is missing on this device.';
      case KeyHealthStatus.invalidated:
        _approvalsLockedReason = 'Your approval key was invalidated: a '
            'fingerprint or face was added or removed on this device.';
      case KeyHealthStatus.healthy:
        final fp = _fingerprint(approval.info.publicKey);
        _approvalsLockedReason =
            fp != null && fp != enrollment.approvalKeyFingerprint
                ? 'The approval key on this device is not the one the bank '
                    'registered.'
                : null;
    }
  }

  static String? _fingerprint(String? publicKey) {
    if (publicKey == null) return null;
    try {
      return ParsedPublicKey.parse(publicKey).fingerprint;
    } on FormatException {
      return null;
    }
  }

  /// Re-probes both keys (after a failure, or on the security screen).
  Future<void> recheckKeys() async {
    await _reconcileKeys();
    notifyListeners();
  }

  /// Fetches accounts with a silently signed request.
  Future<void> refresh() async {
    final enrollment = _enrollment;
    if (enrollment == null || _refreshing) return;
    _refreshing = true;
    notifyListeners();
    try {
      final snapshot = await client.fetchAccounts();
      _snapshot = snapshot;
      refreshError = null;
      final registered = snapshot.device.activeApprovalKey;
      if (registered == null) {
        _approvalsLockedReason ??=
            'The bank has no active approval key for this device.';
      } else if (registered.fingerprint != enrollment.approvalKeyFingerprint) {
        _approvalsLockedReason ??= 'The bank holds a different approval key '
            'than this device.';
      }
    } on BankError catch (e) {
      if (e.deviceNotRecognised) {
        await _loseBinding('The bank no longer recognises this device: '
            '${e.message}');
      } else if (e.kind == BankErrorKind.signing &&
          e.code == BiometricError.keyNotFound) {
        await _loseBinding('The device-binding key is missing on this '
            'device, so the app can no longer sign requests.');
      } else {
        refreshError = e;
      }
    } finally {
      _refreshing = false;
      notifyListeners();
    }
  }

  /// Background refresh (returning to the app, policy changes). Skipped on
  /// Windows, where every request signature shows Windows Hello.
  Future<void> autoRefresh() async {
    if (silentKeysPrompt || !isEnrolled) return;
    await refresh();
  }

  /// Stores a new binding.
  Future<void> completeEnrollment(
    KeyRegistrationResult result, {
    required DeviceEnrollment attempt,
    required bool allowDeviceCredential,
  }) async {
    final enrollment = ClientEnrollment(
      deviceId: result.device.deviceId,
      customerName: attempt.start!.customerName,
      allowDeviceCredential: allowDeviceCredential,
      deviceKeyFingerprint: attempt.deviceKey!.fingerprint,
      approvalKeyFingerprint: attempt.approvalKey!.fingerprint,
      enrolledAt: result.device.enrolledAt,
    );
    await store.write('enrollment', enrollment.toJson());
    _enrollment = enrollment;
    client.deviceId = enrollment.deviceId;
    _bindingLostReason = null;
    _previousDeviceId = null;
    _approvalsLockedReason = null;
    lastRegistration = result;
    await _reconcileKeys();
    notifyListeners();
    if (!silentKeysPrompt) await refresh();
  }

  /// Stores a rotated approval key.
  Future<void> completeReverification(
    KeyRegistrationResult result, {
    required CreatedKey key,
    required bool allowDeviceCredential,
  }) async {
    final enrollment = _enrollment;
    if (enrollment == null) return;
    final updated = enrollment.withApprovalKey(key.fingerprint,
        allowDeviceCredential: allowDeviceCredential);
    await store.write('enrollment', updated.toJson());
    _enrollment = updated;
    _approvalsLockedReason = null;
    _snapshot = _snapshot?.withDevice(result.device);
    lastRegistration = result;
    await _reconcileKeys();
    notifyListeners();
  }

  /// Locks approvals until re-verification.
  void lockApprovals(String reason) {
    _approvalsLockedReason = reason;
    notifyListeners();
  }

  /// Applies balances returned with a transfer decision.
  void applyConfirm(ConfirmResult result) {
    final accounts = result.accounts;
    final recent = result.recent;
    if (_snapshot != null && accounts != null && recent != null) {
      _snapshot = _snapshot!.withActivity(accounts, recent);
      notifyListeners();
    }
  }

  /// Hides the registration summary.
  void dismissRegistration() {
    lastRegistration = null;
    notifyListeners();
  }

  /// The device-binding key is gone: back to onboarding.
  Future<void> bindingLost(String reason) => _loseBinding(reason);

  Future<void> _loseBinding(String reason) async {
    _bindingLostReason = reason;
    _previousDeviceId = _enrollment?.deviceId ?? _previousDeviceId;
    await _clearBinding();
  }

  /// Forgets the binding after a reset or an unbind.
  Future<void> forget({String? reason}) async {
    _bindingLostReason = reason;
    _previousDeviceId = null;
    await _clearBinding();
  }

  Future<void> _clearBinding() async {
    _enrollment = null;
    _snapshot = null;
    _approvalsLockedReason = null;
    deviceKeyHealth = null;
    approvalKeyHealth = null;
    lastRegistration = null;
    refreshError = null;
    client.deviceId = null;
    await store.remove('enrollment');
    notifyListeners();
  }
}
