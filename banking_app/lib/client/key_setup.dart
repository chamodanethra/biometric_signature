/// Creating the two keys and registering them with the bank: device
/// binding at onboarding, and approval-key rotation after re-verification.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';

import '../server/models.dart';
import 'bank_client.dart';

/// What the device offers before any key is created.
class Preflight {
  /// Creates a result.
  const Preflight({
    required this.platform,
    required this.availability,
    required this.deviceLockSet,
  });

  /// The platform.
  final DevicePlatform platform;

  /// `biometricAuthAvailable()`.
  final BiometricAvailability availability;

  /// `isDeviceLockSet()` (Windows: Windows Hello is set up).
  final bool deviceLockSet;

  /// Enrolled biometric types, e.g. `fingerprint, face`.
  String get biometricTypes {
    final types = [
      for (final t
          in availability.availableBiometrics ?? const <BiometricType?>[])
        if (t != null && t != BiometricType.unavailable) t.name,
    ];
    return types.isEmpty ? 'none' : types.join(', ');
  }

  /// Whether biometrics can be used for the approval key.
  bool get biometricsReady => platform == DevicePlatform.windows
      ? availability.canAuthenticate == true
      : availability.canAuthenticate == true &&
          availability.hasEnrolledBiometrics == true;

  /// Whether onboarding can continue.
  bool get canProceed =>
      platform != DevicePlatform.other && deviceLockSet && biometricsReady;

  /// What blocks onboarding, in plain words.
  List<String> get problems => [
        if (platform == DevicePlatform.other)
          'biometric_signature does not support this platform.',
        if (!deviceLockSet)
          platform == DevicePlatform.windows
              ? 'Set up Windows Hello (a PIN at least) in Settings.'
              : 'Set a screen lock (PIN, pattern or passcode) first: keys '
                  'that need user authentication require one.',
        if (deviceLockSet && !biometricsReady)
          availability.hasEnrolledBiometrics == false
              ? 'Enroll a fingerprint or face: the approval key is '
                  'biometric-only.'
              : 'Biometrics are unavailable: '
                  '${availability.reason ?? 'no reason given'}.',
      ];
}

/// A key the plugin just created.
class CreatedKey {
  /// Creates a record.
  CreatedKey({
    required this.alias,
    required this.publicKey,
    required this.attestationChain,
    required this.attestationNote,
    this.useDeviceCredentials,
  });

  /// Alias.
  final String alias;

  /// SPKI DER, base64.
  final String publicKey;

  /// `attestationCertificateChain` (Android only).
  final List<Uint8List>? attestationChain;

  /// Why there is no attestation, if there is none.
  final String? attestationNote;

  /// `useDeviceCredentials` at creation (approval key).
  final bool? useDeviceCredentials;

  late final ParsedPublicKey _parsed = ParsedPublicKey.parse(publicKey);

  /// SHA-256 of the SPKI, hex.
  String get fingerprint => _parsed.fingerprint;

  /// JSON sent to the bank.
  Map<String, dynamic> toRegistrationJson() => {
        'alias': alias,
        'publicKey': publicKey,
        'attestationChain': attestationChain == null
            ? null
            : [for (final c in attestationChain!) base64.encode(c)],
        'attestationNote': attestationNote,
        'useDeviceCredentials': useDeviceCredentials,
      };
}

/// `createKeys` failed.
class KeySetupException implements Exception {
  /// Creates the exception.
  const KeySetupException(this.alias, this.code, this.message);

  /// Alias being created.
  final String alias;

  /// Plugin error code.
  final BiometricError code;

  /// Plugin message.
  final String message;

  /// Attestation keys are not provisioned yet: retry later with a fresh
  /// challenge, or continue unattested.
  bool get attestationNotReady => code == BiometricError.notAvailable;

  @override
  String toString() => 'KeySetupException($alias, ${code.name}): $message';
}

/// Creates the app's keys with the plugin.
class KeySetup {
  /// Creates the helper.
  KeySetup({required this.api, required this.platform});

  /// The plugin.
  final BiometricSignature api;

  /// The platform.
  final DevicePlatform platform;

  /// Whether key attestation is requested (Android only; elsewhere
  /// `attestationChallenge` returns `notSupported`).
  bool get attests => PlatformCapabilities.of(platform).supportsAttestation;

  /// `biometricAuthAvailable()` + `isDeviceLockSet()`.
  Future<Preflight> preflight() async => Preflight(
        platform: platform,
        availability: await api.biometricAuthAvailable(),
        deviceLockSet: await api.isDeviceLockSet(),
      );

  /// Creates the silent `device_binding` key: `requireAuthentication:
  /// false`, so it signs without a prompt (except on Windows).
  Future<CreatedKey> createDeviceBindingKey({List<int>? challenge}) => _create(
        alias: KeyAliases.deviceBinding,
        promptMessage: 'Create this device\'s binding key',
        challenge: challenge,
        config: (attestationChallenge) => CreateKeysConfig(
          signatureType: SignatureType.ecdsa,
          requireAuthentication: false,
          failIfExists: true,
          attestationChallenge: attestationChallenge,
        ),
      );

  /// Creates the biometric `txn_approval` key. It is invalidated when
  /// fingerprints or faces change.
  Future<CreatedKey> createApprovalKey({
    List<int>? challenge,
    required bool allowDeviceCredential,
  }) =>
      _create(
        alias: KeyAliases.approval,
        promptMessage: 'Create your transfer-approval key',
        challenge: challenge,
        useDeviceCredentials: allowDeviceCredential,
        config: (attestationChallenge) => CreateKeysConfig(
          signatureType: SignatureType.ecdsa,
          enforceBiometric: true,
          setInvalidatedByBiometricEnrollment: true,
          useDeviceCredentials: allowDeviceCredential,
          requireAuthentication: true,
          promptSubtitle: 'Step-up Banking',
          promptDescription: 'This key approves transfers over the silent '
              'limit. It stops working if fingerprints or faces change.',
          cancelButtonText: 'Not now',
          failIfExists: true,
          attestationChallenge: attestationChallenge,
        ),
      );

  Future<CreatedKey> _create({
    required String alias,
    required String promptMessage,
    required CreateKeysConfig Function(Uint8List? challenge) config,
    List<int>? challenge,
    bool? useDeviceCredentials,
  }) async {
    final attestationChallenge =
        attests && challenge != null ? Uint8List.fromList(challenge) : null;
    var result = await api.createKeys(
      keyAlias: alias,
      config: config(attestationChallenge),
      promptMessage: promptMessage,
    );
    String? note;
    if (attestationChallenge != null &&
        result.code == BiometricError.notSupported) {
      // This keystore cannot attest keys (Android 6, or no attestation
      // support). Attestation never silently degrades, so create the key
      // again without a challenge and tell the bank it is unattested.
      note = 'This device\'s keystore cannot attest keys (notSupported), so '
          'the key was registered without attestation.';
      result = await api.createKeys(
        keyAlias: alias,
        config: config(null),
        promptMessage: promptMessage,
      );
    }
    final publicKey = result.publicKey;
    if (result.code != BiometricError.success || publicKey == null) {
      throw KeySetupException(alias, result.code ?? BiometricError.unknown,
          result.error ?? 'createKeys failed');
    }
    if (attestationChallenge == null) {
      note ??= attests
          ? 'Created without attestation at the user\'s request.'
          : '${platform.label} has no per-key attestation: the bank cannot '
              'verify how this key is protected.';
    }
    final chain = result.attestationCertificateChain;
    return CreatedKey(
      alias: alias,
      publicKey: publicKey,
      attestationChain: chain == null || chain.isEmpty ? null : chain,
      attestationNote: note,
      useDeviceCredentials: useDeviceCredentials,
    );
  }

  /// Deletes the key under [alias] (`deleteKeys`).
  Future<void> deleteKey(String alias) => api.deleteKeys(keyAlias: alias);

  /// `getKeyInfo(checkValidity: true)` for [alias].
  Future<KeyHealth> probe(String alias) => probeKey(api, alias: alias);
}

/// One attempt at binding this device (onboarding).
class DeviceEnrollment {
  /// Creates an attempt.
  DeviceEnrollment({
    required this.keys,
    required this.client,
    this.previousDeviceId,
  });

  /// Key helper.
  final KeySetup keys;

  /// Bank client.
  final BankClient client;

  /// A binding this enrollment replaces (the bank revokes it).
  final String? previousDeviceId;

  /// The bank's response to [begin].
  EnrollmentStart? start;

  /// Keys created during this attempt (kept for retries).
  CreatedKey? deviceKey;

  /// Keys created during this attempt (kept for retries).
  CreatedKey? approvalKey;

  /// Create keys without attestation (after `notAvailable`).
  bool skipAttestation = false;

  /// Asks the bank for a one-time code and fresh attestation challenges.
  /// Keys created by an earlier call were attested with the old
  /// challenges, so they are deleted.
  Future<EnrollmentStart> begin() async {
    await discardCreatedKeys();
    final s = await client.enrollBegin(
        platform: keys.platform, previousDeviceId: previousDeviceId);
    start = s;
    return s;
  }

  /// Creates whatever key is still missing and registers both with the
  /// bank. Throws [KeySetupException] or [BankError]; keys created so far
  /// are kept, so calling again retries only what failed.
  Future<KeyRegistrationResult> complete({
    required String otp,
    required bool allowDeviceCredential,
    void Function(String step)? onStep,
  }) async {
    final s = start;
    if (s == null) throw StateError('Call begin() first');
    List<int>? challenge(String alias) =>
        skipAttestation ? null : s.challengeFor(alias);

    onStep?.call('Creating the device-binding key (silent)…');
    final device = deviceKey ??= await keys.createDeviceBindingKey(
        challenge: challenge(KeyAliases.deviceBinding));

    if (approvalKey != null &&
        approvalKey!.useDeviceCredentials != allowDeviceCredential) {
      await keys.deleteKey(KeyAliases.approval);
      approvalKey = null;
    }
    onStep?.call('Creating the approval key — confirm with your biometric…');
    final approval = approvalKey ??= await keys.createApprovalKey(
      challenge: challenge(KeyAliases.approval),
      allowDeviceCredential: allowDeviceCredential,
    );

    onStep?.call('The bank is verifying both keys…');
    return client.enrollFinish({
      'enrollmentId': s.enrollmentId,
      'otp': otp.trim(),
      'deviceKey': device.toRegistrationJson(),
      'approvalKey': approval.toRegistrationJson(),
    });
  }

  /// Deletes a key left by an earlier install (after `keyAlreadyExists`).
  Future<void> replaceExisting(String alias) => keys.deleteKey(alias);

  /// Deletes keys this attempt created but did not register.
  Future<void> discardCreatedKeys() async {
    if (deviceKey != null) await keys.deleteKey(KeyAliases.deviceBinding);
    if (approvalKey != null) await keys.deleteKey(KeyAliases.approval);
    deviceKey = null;
    approvalKey = null;
  }
}

/// Re-verification: prove the device with the silent key, prove the person
/// with a one-time code, then register a new approval key.
class ApprovalKeyReverification {
  /// Creates an attempt.
  ApprovalKeyReverification({
    required this.keys,
    required this.client,
    required this.reason,
  });

  /// Key helper.
  final KeySetup keys;

  /// Bank client.
  final BankClient client;

  /// Why (`keyInvalidated`, `rotation` …), recorded by the bank.
  final String reason;

  /// The bank's response to [begin].
  ReverifyStart? start;

  /// The new key, once created.
  CreatedKey? newKey;

  /// Asks the bank for a one-time code and an attestation challenge. The
  /// request is signed by `device_binding`, which enrollment changes do not
  /// invalidate.
  Future<ReverifyStart> begin() async {
    if (newKey != null) {
      await keys.deleteKey(KeyAliases.approval);
      newKey = null;
    }
    final s = await client.reverifyBegin(reason);
    start = s;
    return s;
  }

  /// Replaces the local approval key and registers the new one.
  ///
  /// The plugin holds one key per alias, so the old (invalidated or
  /// rotated) key is deleted before `createKeys(failIfExists: true)`.
  Future<KeyRegistrationResult> complete({
    required String otp,
    required bool allowDeviceCredential,
    bool skipAttestation = false,
    void Function(String step)? onStep,
  }) async {
    final s = start;
    if (s == null) throw StateError('Call begin() first');
    if (newKey == null) {
      onStep?.call('Removing the old approval key…');
      await keys.deleteKey(KeyAliases.approval);
      onStep?.call('Creating a new approval key — confirm with your '
          'biometric…');
      newKey = await keys.createApprovalKey(
        challenge: skipAttestation ? null : s.challenge,
        allowDeviceCredential: allowDeviceCredential,
      );
    }
    onStep?.call('The bank is verifying the new key…');
    return client.reverifyFinish({
      'reverifyId': s.reverifyId,
      'otp': otp.trim(),
      'approvalKey': newKey!.toRegistrationJson(),
    });
  }
}
