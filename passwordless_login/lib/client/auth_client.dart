import 'dart:convert';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/foundation.dart';

import '../server/models.dart';
import 'accounts.dart';
import 'aliases.dart';
import 'outcome.dart';
import 'preflight.dart';
import 'reconcile.dart';

/// Reports what a long-running flow is doing (attestation can take seconds).
typedef ProgressCallback = void Function(String step);

/// How a new key is created.
@immutable
class KeyOptions {
  /// Creates options. The defaults are the strict ones.
  const KeyOptions({
    this.allowDeviceCredentials = false,
    this.invalidateOnEnrollment = true,
  });

  /// `useDeviceCredentials`: the PIN / passcode can also unlock the key.
  /// Off: biometric only (on Android the attestation then proves
  /// `userAuthType` = biometric).
  final bool allowDeviceCredentials;

  /// `setInvalidatedByBiometricEnrollment`: enrolling a new fingerprint or
  /// face permanently invalidates the key. On iOS/macOS a key that also
  /// allows the passcode is never invalidated.
  final bool invalidateOnEnrollment;
}

/// A completed registration or recovery.
class Registration {
  /// Creates a result.
  const Registration({
    required this.account,
    required this.report,
    required this.recoveryCode,
    this.isRecovery = false,
    this.superseded = const [],
  });

  /// The new local account.
  final LocalAccount account;

  /// The server's attestation report.
  final AttestationReport report;

  /// The one-time recovery code (shown once, stored only as a hash).
  final String recoveryCode;

  /// Whether this bound a replacement key to an existing account.
  final bool isRecovery;

  /// Device keys the server retired.
  final List<String> superseded;
}

/// A completed sign-in.
class SignIn {
  /// Creates a result.
  const SignIn({
    required this.session,
    required this.account,
    this.restored = false,
  });

  /// The server session.
  final SessionRecord session;

  /// The account (updated).
  final LocalAccount account;

  /// Whether the account was restored from a key already on the device.
  final bool restored;
}

/// Everything a sign-in exchanged, for the signing-trace screen.
class LoginTrace extends ChangeNotifier {
  /// Creates an empty trace for [username].
  LoginTrace(this.username);

  /// Username being signed in.
  final String username;

  /// User id from `/login/begin`.
  String? userId;

  /// Challenge id.
  String? challengeId;

  /// Nonce, base64.
  String? nonce;

  /// Nonce expiry (server clock).
  DateTime? expiresAt;

  /// Relying-party string.
  String? rp;

  /// Key alias used.
  String? alias;

  /// Server device key id used.
  String? deviceKeyId;

  /// Whether the key was found from the server's list (restore).
  bool restored = false;

  /// The canonical JSON that was signed.
  String? payloadJson;

  /// Its bytes.
  Uint8List? payloadBytes;

  /// The signature, base64.
  String? signature;

  /// `SignatureResult.algorithm`.
  String? algorithm;

  /// `SignatureResult.keySize`.
  int? keySize;

  /// `SignatureResult.authenticationType` (client-reported).
  AuthenticationType? authenticationType;

  /// The server's verification steps.
  List<AttestationCheck> checks = const [];

  /// `true` accepted, `false` rejected, `null` not verified yet.
  bool? accepted;

  /// Signals a change.
  void changed() => notifyListeners();
}

/// The device side of the protocol: drives the plugin and talks to the
/// server over [transport].
///
/// Every method returns an [AuthOutcome] instead of throwing; plugin errors
/// arrive in `result.code`, never as exceptions.
class AuthClient {
  /// Creates a client.
  AuthClient({
    required this.api,
    required this.transport,
    required this.accounts,
    required this.platform,
  });

  /// The plugin.
  final BiometricSignature api;

  /// The wire to the server.
  final MockTransport transport;

  /// Local accounts.
  final AccountRepository accounts;

  /// The running platform.
  final DevicePlatform platform;

  /// What the platform can do.
  PlatformCapabilities get capabilities => PlatformCapabilities.of(platform);

  /// Screen lock and biometric enrollment.
  Future<PreflightResult> preflight() => runPreflight(api, platform);

  /// Reconciles local accounts with the device's keys and the server.
  Future<void> reconcile() =>
      reconcileAll(api: api, transport: transport, accounts: accounts);

  // ---------------------------------------------------------------------
  // Registration

  /// Registers [username] with a new attested key under [alias].
  ///
  /// With [replaceExistingKey], the key under [alias] is deleted first —
  /// only after the user confirmed it (the flow otherwise uses
  /// `failIfExists: true`, which never overwrites a key).
  Future<AuthOutcome<Registration>> register({
    required String username,
    required String alias,
    KeyOptions options = const KeyOptions(),
    bool replaceExistingKey = false,
    ProgressCallback? onProgress,
  }) async {
    final name = normalizeUsername(username);
    final problem = usernameProblem(name);
    if (problem != null) {
      return Rejected(problem, code: ServerErrors.badRequest);
    }
    // Starting over abandons an earlier key whose upload never completed.
    await discardPending();
    onProgress?.call('Requesting an attestation challenge…');
    final begin = await _call(
        ApiRoutes.registerBegin, {'username': name, 'platform': platform.name});
    if (begin is! Success<Map<String, dynamic>>) return begin.castFailure();
    final challenge = begin.value;

    final created = await _createKey(
      alias: alias,
      promptMessage: 'Create a sign-in key for $name',
      challenge: base64.decode(challenge['challenge'] as String),
      attestationRequired: challenge['attestation'] == 'required',
      options: options,
      replaceExistingKey: replaceExistingKey,
      onProgress: onProgress,
    );
    if (created is! Success<_NewKey>) return created.castFailure();

    final pending = PendingUpload(
      kind: UploadKind.register,
      alias: alias,
      username: name,
      challengeId: challenge['challengeId'] as String,
      expiresAt: DateTime.parse(challenge['expiresAt'] as String),
      allowDeviceCredentials: options.allowDeviceCredentials,
      invalidateOnEnrollment: options.invalidateOnEnrollment,
    );
    await accounts.setPending(pending);
    return _upload(pending, created.value, onProgress);
  }

  /// Binds a new key to an existing account with its one-time
  /// [recoveryCode]. The server verifies a fresh attestation, retires the
  /// old key(s) and rotates the recovery code.
  ///
  /// When [replacing] is given, the new key reuses its alias; if the old key
  /// is still stored there, the result is [Blocked] with
  /// `keyAlreadyExists` until the call is repeated with
  /// [replaceExistingKey].
  Future<AuthOutcome<Registration>> recover({
    required String username,
    required String recoveryCode,
    LocalAccount? replacing,
    KeyOptions options = const KeyOptions(),
    bool replaceExistingKey = false,
    ProgressCallback? onProgress,
  }) async {
    final name = normalizeUsername(username);
    final problem = usernameProblem(name);
    if (problem != null) {
      return Rejected(problem, code: ServerErrors.badRequest);
    }
    await discardPending();
    onProgress?.call('Checking the recovery code…');
    final begin = await _call(ApiRoutes.recoveryBegin, {
      'username': name,
      'recoveryCode': recoveryCode,
      'platform': platform.name,
    });
    if (begin is! Success<Map<String, dynamic>>) return begin.castFailure();
    final challenge = begin.value;

    var old = replacing;
    if (old == null) {
      for (final a in accounts.accounts) {
        if (a.username == name) old = a;
      }
    }
    final alias = old?.alias ?? newAccountAlias();
    final created = await _createKey(
      alias: alias,
      promptMessage: 'Create a new sign-in key for $name',
      challenge: base64.decode(challenge['challenge'] as String),
      attestationRequired: challenge['attestation'] == 'required',
      options: options,
      replaceExistingKey: replaceExistingKey,
      onProgress: onProgress,
    );
    if (created is! Success<_NewKey>) return created.castFailure();

    final pending = PendingUpload(
      kind: UploadKind.recovery,
      alias: alias,
      username: name,
      challengeId: challenge['challengeId'] as String,
      expiresAt: DateTime.parse(challenge['expiresAt'] as String),
      allowDeviceCredentials: options.allowDeviceCredentials,
      invalidateOnEnrollment: options.invalidateOnEnrollment,
      recoveryCode: recoveryCode,
      replacing: old?.alias,
    );
    await accounts.setPending(pending);
    return _upload(pending, created.value, onProgress);
  }

  /// Re-sends a registration whose upload failed. The public key and the
  /// attestation chain are read back from the device with `getKeyInfo`;
  /// the server kept the challenge, because it only consumes it once a
  /// registration succeeds.
  Future<AuthOutcome<Registration>> retryUpload(
      {ProgressCallback? onProgress}) async {
    final pending = accounts.pending;
    if (pending == null) {
      return const Rejected('There is no registration waiting to be sent.');
    }
    if (pending.kind == UploadKind.recovery && pending.recoveryCode == null) {
      await discardPending();
      return const Rejected('The recovery code was not kept after the app '
          'restarted. Start the recovery again.');
    }
    onProgress?.call('Reading the public key and attestation chain back '
        'with getKeyInfo…');
    final info = await api.getKeyInfo(keyAlias: pending.alias);
    final publicKey = info.publicKey;
    if (info.exists != true || publicKey == null) {
      await accounts.setPending(null);
      return Retryable(
        guidanceFor(BiometricError.keyNotFound),
        rawMessage: 'The key under ${pending.alias} is gone. Start again '
            'with a fresh challenge.',
        retry: RetryKind.freshChallenge,
      );
    }
    return _upload(
      pending,
      _NewKey(publicKey, info.attestationCertificateChain ?? const [], null),
      onProgress,
    );
  }

  /// Deletes the key of a pending upload and forgets it.
  Future<void> discardPending() async {
    final pending = accounts.pending;
    if (pending == null) return;
    await api.deleteKeys(keyAlias: pending.alias);
    await accounts.setPending(null);
    _markMissing(pending.alias, 'The replacement key was discarded.');
  }

  CreateKeysConfig _keysConfig(KeyOptions options, Uint8List? challenge) =>
      CreateKeysConfig(
        // Windows ignores this and creates an RSA-2048 Windows Hello key.
        signatureType: SignatureType.ecdsa,
        enforceBiometric: true,
        // Never silently overwrite a key another flow still relies on.
        failIfExists: true,
        useDeviceCredentials: options.allowDeviceCredentials,
        setInvalidatedByBiometricEnrollment: options.invalidateOnEnrollment,
        promptSubtitle: 'Passwordless Login',
        promptDescription: 'Confirm it is you to create this account’s '
            'sign-in key. The private key never leaves secure hardware.',
        cancelButtonText: 'Not now',
        // Android only; other platforms would return notSupported.
        attestationChallenge: challenge,
      );

  Future<AuthOutcome<_NewKey>> _createKey({
    required String alias,
    required String promptMessage,
    required Uint8List challenge,
    required bool attestationRequired,
    required KeyOptions options,
    required bool replaceExistingKey,
    ProgressCallback? onProgress,
  }) async {
    if (replaceExistingKey) await api.deleteKeys(keyAlias: alias);
    final attest = capabilities.supportsAttestation;
    onProgress?.call(attest
        ? 'Creating the key in secure hardware with attestation…'
        : 'Creating the key…');
    var result = await api.createKeys(
      keyAlias: alias,
      promptMessage: promptMessage,
      config: _keysConfig(options, attest ? challenge : null),
    );
    if (attest && result.code == BiometricError.notSupported) {
      // This keystore cannot attest (Android 6, some emulators). Nothing was
      // lost: failIfExists is checked before anything is deleted.
      if (attestationRequired) {
        return Rejected(
          'This device’s keystore cannot attest keys (notSupported), and '
          'the server requires attestation. Turn off "Require attestation" '
          'in the server console to register it as unattested.',
          code: ServerErrors.attestationRequired,
        );
      }
      onProgress?.call('This keystore cannot attest; creating an '
          'unattested key…');
      result = await api.createKeys(
        keyAlias: alias,
        promptMessage: promptMessage,
        config: _keysConfig(options, null),
      );
    }
    final publicKey = result.publicKey;
    if (result.code != BiometricError.success) {
      return _pluginFailure(result.code, result.error,
          notAvailableRetry: RetryKind.freshChallenge);
    }
    if (publicKey == null) {
      return Retryable(guidanceFor(BiometricError.unknown),
          rawMessage: 'createKeys returned no public key.');
    }
    return Success(_NewKey(
      publicKey,
      result.attestationCertificateChain ?? const [],
      result.authenticationType,
    ));
  }

  Future<AuthOutcome<Registration>> _upload(
    PendingUpload pending,
    _NewKey key,
    ProgressCallback? onProgress,
  ) async {
    onProgress?.call(key.chain.isEmpty
        ? 'Registering the public key…'
        : 'Uploading the key and its attestation; the server is verifying '
            'the chain…');
    final isRecovery = pending.kind == UploadKind.recovery;
    final response = await _call(
      isRecovery ? ApiRoutes.recoveryFinish : ApiRoutes.registerFinish,
      {
        'username': pending.username,
        if (isRecovery) 'recoveryCode': pending.recoveryCode,
        'challengeId': pending.challengeId,
        'alias': pending.alias,
        'platform': platform.name,
        'publicKey': key.publicKey,
        'attestationChain': key.chain.isEmpty
            ? null
            : [for (final c in key.chain) base64.encode(c)],
        'authenticationType': key.authenticationType?.name,
        'allowDeviceCredentials': pending.allowDeviceCredentials,
        'invalidateOnEnrollment': pending.invalidateOnEnrollment,
      },
    );
    switch (response) {
      case Retryable(:final rawMessage):
        // The key exists; only the upload failed. Keep both.
        return Retryable(null,
            rawMessage: rawMessage, retry: RetryKind.reupload);
      case Success(:final value):
        final account = LocalAccount(
          alias: pending.alias,
          userId: value['userId'] as String,
          username: value['username'] as String,
          deviceKeyId: value['deviceKeyId'] as String,
          trustTier: TrustTier.values.byName(value['trustTier'] as String),
          publicKeyFingerprint:
              ParsedPublicKey.parse(key.publicKey).fingerprint,
          allowDeviceCredentials: pending.allowDeviceCredentials,
          invalidateOnEnrollment: pending.invalidateOnEnrollment,
          registeredAt: DateTime.now().toUtc(),
        );
        final replaced = pending.replacing;
        if (replaced != null && replaced != pending.alias) {
          await api.deleteKeys(keyAlias: replaced);
          await accounts.remove(replaced);
        }
        await accounts.upsert(account,
            status: const AccountStatus(
                AccountState.ready, 'Bound to this device just now.'));
        await accounts.setPending(null);
        return Success(Registration(
          account: account,
          report: AttestationReport.fromJson(
              value['report'] as Map<String, dynamic>),
          recoveryCode: value['recoveryCode'] as String,
          isRecovery: isRecovery,
          superseded: [
            for (final s in value['superseded'] as List? ?? const [])
              s as String,
          ],
        ));
      case NeedsRebind() || Blocked() || Rejected():
        // The server refused this key for good: it is useless, delete it.
        await api.deleteKeys(keyAlias: pending.alias);
        await accounts.setPending(null);
        _markMissing(pending.alias,
            'The replacement key was rejected by the server and deleted.');
        return response.castFailure();
    }
  }

  void _markMissing(String alias, String message) {
    if (accounts.byAlias(alias) != null) {
      accounts.setStatus(
          alias, AccountStatus(AccountState.keyMissing, message));
    }
  }

  // ---------------------------------------------------------------------
  // Sign-in

  /// Signs in by signing a single-use server nonce.
  ///
  /// With [account], its key is used. Without, the server's list of the
  /// account's keys is searched for one already on this device (an iOS
  /// keychain key that survived a reinstall) and the account is restored.
  Future<AuthOutcome<SignIn>> login({
    required String username,
    LocalAccount? account,
    LoginTrace? trace,
  }) async {
    final t = trace ?? LoginTrace(username);
    final name = normalizeUsername(username);
    final begin = await _call(ApiRoutes.loginBegin, {'username': name});
    if (begin is! Success<Map<String, dynamic>>) {
      if (account != null &&
          begin is Rejected<Map<String, dynamic>> &&
          begin.code == ServerErrors.deviceInactive) {
        return _serverRetired(account, begin.reason);
      }
      return begin.castFailure();
    }
    final c = begin.value;
    t
      ..userId = c['userId'] as String
      ..challengeId = c['challengeId'] as String
      ..nonce = c['nonce'] as String
      ..rp = c['rp'] as String
      ..expiresAt = DateTime.parse(c['expiresAt'] as String)
      ..changed();

    final devices = [
      for (final d in c['devices'] as List) d as Map<String, dynamic>,
    ];
    var local = account;
    Map<String, dynamic>? device;
    if (local != null) {
      for (final d in devices) {
        if (d['deviceKeyId'] == local.deviceKeyId) device = d;
      }
      if (device == null) {
        return _serverRetired(
            local, 'The server no longer lists this key for "$name".');
      }
    } else {
      for (final d in devices) {
        final alias = d['alias'] as String;
        if (!isValidAlias(alias)) continue;
        if ((await probeKey(api, alias: alias)).isHealthy) {
          device = d;
          break;
        }
      }
      if (device == null) {
        return NeedsRebind(
            'None of the keys registered for "$name" is on this device. Use '
            'the recovery code to bind this device.');
      }
      local = accounts.byAlias(device['alias'] as String);
      t.restored = local == null;
    }
    final alias = device['alias'] as String;
    final deviceKeyId = device['deviceKeyId'] as String;
    final allowCredential = local?.allowDeviceCredentials ??
        device['allowDeviceCredentials'] as bool? ??
        false;

    final fields = signedChallengeFields(
      purpose: Purposes.login,
      rp: t.rp!,
      userId: t.userId!,
      challengeId: t.challengeId!,
      nonceBase64: t.nonce!,
    );
    final payload = canonicalJsonBytes(fields);
    t
      ..alias = alias
      ..deviceKeyId = deviceKeyId
      ..payloadJson = canonicalJson(fields)
      ..payloadBytes = payload
      ..changed();

    final result = await api.createSignatureFromBytes(
      payload: payload,
      keyAlias: alias,
      promptMessage: 'Sign in as $name',
      config: CreateSignatureConfig(
        promptSubtitle: 'Passwordless Login',
        promptDescription: 'Signs a one-time challenge from the server. Only '
            'the signature leaves this device.',
        cancelButtonText: 'Cancel',
        allowDeviceCredentials: allowCredential,
      ),
    );
    final signature = result.signature;
    if (result.code != BiometricError.success || signature == null) {
      return _signingFailure(result.code, result.error, alias, local);
    }
    t
      ..signature = signature
      ..algorithm = result.algorithm
      ..keySize = result.keySize
      ..authenticationType = result.authenticationType
      ..changed();

    final finish = await _call(ApiRoutes.loginFinish, {
      'userId': t.userId,
      'deviceKeyId': deviceKeyId,
      'challengeId': t.challengeId,
      'signature': signature,
      'authenticationType': result.authenticationType?.name,
    });
    switch (finish) {
      case Success(:final value):
        t
          ..checks = _checks(value['checks'])
          ..accepted = true
          ..changed();
        final session =
            SessionRecord.fromJson(value['session'] as Map<String, dynamic>);
        final now = DateTime.now().toUtc();
        final updated = local?.signedIn(now, result.authenticationType) ??
            LocalAccount(
              alias: alias,
              userId: session.userId,
              username: session.username,
              deviceKeyId: deviceKeyId,
              trustTier: session.trustTier,
              publicKeyFingerprint:
                  ParsedPublicKey.parse(result.publicKey!).fingerprint,
              allowDeviceCredentials: allowCredential,
              invalidateOnEnrollment:
                  device['invalidateOnEnrollment'] as bool? ?? true,
              registeredAt: now,
              lastLoginAt: now,
              lastAuthenticationType: result.authenticationType,
            );
        await accounts.upsert(updated,
            status:
                const AccountStatus(AccountState.ready, 'Signed in just now.'));
        return Success(SignIn(
            session: session, account: updated, restored: local == null));
      case Rejected(:final checks, :final code, :final reason):
        t
          ..checks = checks
          ..accepted = false
          ..changed();
        if (code == ServerErrors.deviceInactive && local != null) {
          return _serverRetired(local, reason);
        }
        return finish.castFailure();
      case Retryable() || Blocked() || NeedsRebind():
        return finish.castFailure();
    }
  }

  Future<AuthOutcome<T>> _serverRetired<T>(
      LocalAccount account, String reason) async {
    final status = AccountStatus(AccountState.serverInactive,
        '$reason It was replaced with the recovery code or unbound.');
    accounts.setStatus(account.alias, status);
    return NeedsRebind(status.message, account: account);
  }

  /// Maps a failed signature. `keyInvalidated`, `keyNotFound` and any
  /// unexpected error are double-checked with `getKeyInfo(checkValidity:
  /// true)` before telling the user to re-bind.
  Future<AuthOutcome<T>> _signingFailure<T>(BiometricError? code, String? raw,
      String alias, LocalAccount? account) async {
    final guidance = guidanceFor(code);
    final expected = guidance.isTransient ||
        code == BiometricError.lockedOutPermanent ||
        code == BiometricError.securityUpdateRequired;
    if (expected) return _pluginFailure(code, raw);
    final health = await probeKey(api, alias: alias);
    final keyGone = code == BiometricError.keyInvalidated ||
        code == BiometricError.keyNotFound ||
        !health.isHealthy;
    if (!keyGone) return _pluginFailure(code, raw);
    final status = AccountStatus(
      health.status == KeyHealthStatus.missing
          ? AccountState.keyMissing
          : AccountState.keyInvalidated,
      '${guidance.title}: ${guidance.message}',
      health: health,
    );
    if (account != null) accounts.setStatus(account.alias, status);
    return NeedsRebind(status.message, account: account, health: health);
  }

  /// After `lockedOutPermanent` on Android: unlock biometrics with the
  /// device credential through `simplePrompt`, then sign again.
  Future<AuthOutcome<void>> unlockWithDeviceCredential() async {
    final result = await api.simplePrompt(
      promptMessage: 'Unlock biometrics',
      config: SimplePromptConfig(
        subtitle: 'Too many failed attempts',
        description: 'Enter your device PIN, pattern or password. Then sign '
            'in again.',
        cancelButtonText: 'Cancel',
        allowDeviceCredentials: true,
      ),
    );
    if (result.success == true) return const Success<void>(null);
    return _pluginFailure(result.code, result.error);
  }

  /// Ends a session on the server.
  Future<void> logout(SessionRecord session) async {
    await _call(ApiRoutes.logout, {'token': session.token});
  }

  // ---------------------------------------------------------------------
  // Devices

  /// The server's record of [account]'s key.
  Future<AuthOutcome<DeviceKeyRecord>> fetchDeviceRecord(
      LocalAccount account) async {
    final response = await _call(ApiRoutes.deviceStatus, {
      'userId': account.userId,
      'deviceKeyId': account.deviceKeyId,
    });
    if (response is! Success<Map<String, dynamic>>) {
      return response.castFailure();
    }
    return Success(DeviceKeyRecord.fromJson(
        response.value['device'] as Map<String, dynamic>));
  }

  /// Unbinds [account]'s key on the server with a signed request, then
  /// deletes the key and the local account.
  ///
  /// If the key cannot sign any more ([NeedsRebind]), use [forgetLocally].
  Future<AuthOutcome<void>> removeFromDevice(LocalAccount account) async {
    final begin = await _call(ApiRoutes.unbindBegin, {
      'userId': account.userId,
      'deviceKeyId': account.deviceKeyId,
    });
    if (begin is! Success<Map<String, dynamic>>) {
      if (begin is Rejected<Map<String, dynamic>> &&
          begin.code == ServerErrors.deviceInactive) {
        // The server already stopped accepting it: just clean up.
        await forgetLocally(account);
        return const Success<void>(null);
      }
      return begin.castFailure();
    }
    final c = begin.value;
    final challengeId = c['challengeId'] as String;
    final payload = signedChallengePayload(
      purpose: Purposes.unbind,
      rp: c['rp'] as String,
      userId: account.userId,
      challengeId: challengeId,
      nonceBase64: c['nonce'] as String,
    );
    final result = await api.createSignatureFromBytes(
      payload: payload,
      keyAlias: account.alias,
      promptMessage: 'Remove ${account.username} from this device',
      config: CreateSignatureConfig(
        promptSubtitle: 'Passwordless Login',
        promptDescription: 'Signs a one-time request asking the server to '
            'stop accepting this device.',
        cancelButtonText: 'Keep',
        allowDeviceCredentials: account.allowDeviceCredentials,
      ),
    );
    final signature = result.signature;
    if (result.code != BiometricError.success || signature == null) {
      return _signingFailure(result.code, result.error, account.alias, account);
    }
    final finish = await _call(ApiRoutes.unbindFinish, {
      'userId': account.userId,
      'deviceKeyId': account.deviceKeyId,
      'challengeId': challengeId,
      'signature': signature,
    });
    if (finish is! Success<Map<String, dynamic>>) return finish.castFailure();
    await forgetLocally(account);
    return const Success<void>(null);
  }

  /// Deletes [account]'s key and local record without telling the server
  /// (its record stays, orphaned).
  Future<void> forgetLocally(LocalAccount account) async {
    await api.deleteKeys(keyAlias: account.alias);
    await accounts.remove(account.alias);
  }

  /// Deletes every key of this app (`deleteAllKeys`) and all local
  /// accounts. The server's records remain and show up as orphaned.
  Future<void> wipeDevice() async {
    await api.deleteAllKeys();
    await accounts.clearAll();
  }

  // ---------------------------------------------------------------------
  // Helpers

  Future<AuthOutcome<Map<String, dynamic>>> _call(
      String route, Map<String, dynamic> body) async {
    final Map<String, dynamic> response;
    try {
      response = await transport.call(route, body);
    } on TransportException catch (e) {
      return Retryable(null, rawMessage: e.message);
    }
    if (response['ok'] == true) return Success(response);
    final report = response['report'];
    return Rejected(
      response['reason'] as String? ?? 'Rejected by the server.',
      code: response['error'] as String?,
      report: report is Map<String, dynamic>
          ? AttestationReport.fromJson(report)
          : null,
      checks: _checks(response['checks']),
    );
  }

  static List<AttestationCheck> _checks(Object? json) => [
        if (json is List)
          for (final c in json)
            AttestationCheck.fromJson(c as Map<String, dynamic>),
      ];

  static AuthOutcome<T> _pluginFailure<T>(
    BiometricError? code,
    String? raw, {
    RetryKind notAvailableRetry = RetryKind.again,
  }) {
    final guidance = guidanceFor(code);
    switch (guidance.action) {
      case RecoveryAction.retry || RecoveryAction.retryLater:
        return Retryable(
          guidance,
          rawMessage: raw,
          retry: code == BiometricError.notAvailable
              ? notAvailableRetry
              : RetryKind.again,
        );
      case RecoveryAction.recreateKey:
        return NeedsRebind(guidance.message);
      case RecoveryAction.none ||
            RecoveryAction.enrollBiometrics ||
            RecoveryAction.setDeviceLock ||
            RecoveryAction.useDeviceCredential ||
            RecoveryAction.updateOs ||
            RecoveryAction.chooseDifferentAlias ||
            RecoveryAction.fixInput ||
            RecoveryAction.unsupportedOnDevice:
        return Blocked(guidance, rawMessage: raw);
    }
  }
}

class _NewKey {
  const _NewKey(this.publicKey, this.chain, this.authenticationType);

  final String publicKey;
  final List<Uint8List> chain;
  final AuthenticationType? authenticationType;
}
