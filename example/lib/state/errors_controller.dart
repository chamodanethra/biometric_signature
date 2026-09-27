import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';

import 'controller_base.dart';
import 'key_alias.dart';
import 'result_fields.dart';

/// The one-tap error triggers and walkthrough steps on the Errors screen.
enum ErrorTrigger {
  /// createKeys twice on a scratch alias, the second with failIfExists.
  keyAlreadyExists,

  /// createKeys with a 129-byte attestation challenge (Android).
  invalidInputChallenge,

  /// createSignatureFromBytes with an empty payload.
  invalidInputEmptyPayload,

  /// createKeys with an attestation challenge outside Android.
  notSupportedAttestation,

  /// deleteKeys then createSignatureFromBytes on an unused alias.
  keyNotFound,

  /// simplePrompt that the user cancels.
  userCanceled,

  /// simplePrompt that the user fails until lockout.
  lockedOut,

  /// keyInvalidated walkthrough, step 1: create the key.
  invalidationCreate,

  /// keyInvalidated walkthrough, step 3: sign with it.
  invalidationSign,

  /// keyInvalidated walkthrough, step 4: getKeyInfo(checkValidity: true).
  invalidationCheck,
}

/// What a trigger produced.
class TriggerOutcome {
  /// Creates an outcome.
  const TriggerOutcome({
    required this.summary,
    required this.asExpected,
    this.code,
    this.error,
  });

  /// One-line summary.
  final String summary;

  /// Whether the platform returned what the trigger aims for.
  final bool asExpected;

  /// The code returned.
  final BiometricError? code;

  /// The plugin's error message.
  final String? error;
}

/// Errors screen: triggers for error codes.
class ErrorsController extends ExplorerController {
  /// Creates the controller.
  ErrorsController(super.state);

  /// Operation id for [trigger].
  static String triggerOp(ErrorTrigger t) => 'trigger:${t.name}';

  /// Last outcome per trigger.
  final Map<ErrorTrigger, TriggerOutcome> outcomes = {};

  SignatureType get _signatureType => state.capabilities.supportsEcKeys
      ? SignatureType.ecdsa
      : SignatureType.rsa;

  static TriggerOutcome _expect(
    BiometricError expected,
    BiometricError? code,
    String? error, {
    Set<BiometricError> alsoAccepted = const {},
    String? successHint,
  }) {
    final got = code ?? BiometricError.success;
    final ok = got == expected || alsoAccepted.contains(got);
    final String summary;
    if (ok) {
      summary = 'Got ${got.name}, as expected.';
    } else if (got == BiometricError.success && successHint != null) {
      summary = 'Got success. $successHint';
    } else {
      summary = 'Expected ${expected.name}, got ${got.name}.';
    }
    return TriggerOutcome(
      summary: summary,
      asExpected: ok,
      code: code,
      error: error,
    );
  }

  /// Runs [t].
  Future<void> trigger(ErrorTrigger t) => run(triggerOp(t), () async {
        outcomes.remove(t);
        notifyListeners();
        outcomes[t] = await _run(t);
      });

  Future<TriggerOutcome> _run(ErrorTrigger t) async {
    switch (t) {
      case ErrorTrigger.keyAlreadyExists:
        return _keyAlreadyExists();
      case ErrorTrigger.invalidInputChallenge:
        final r = await api.createKeys(
          keyAlias: KeyAlias.errorsScratch.value,
          config: CreateKeysConfig(
            signatureType: _signatureType,
            attestationChallenge: secureRandomBytes(129),
          ),
          promptMessage: 'Explorer: invalid attestation challenge',
        );
        await _cleanUpScratch(r.code);
        return _expect(BiometricError.invalidInput, r.code, r.error);
      case ErrorTrigger.invalidInputEmptyPayload:
        final r = await api.createSignatureFromBytes(
          payload: Uint8List(0),
          keyAlias: state.selectedAlias.value,
          promptMessage: 'Explorer: empty payload',
        );
        return _expect(BiometricError.invalidInput, r.code, r.error);
      case ErrorTrigger.notSupportedAttestation:
        final r = await api.createKeys(
          keyAlias: KeyAlias.errorsScratch.value,
          config: CreateKeysConfig(
            signatureType: _signatureType,
            attestationChallenge: secureRandomBytes(32),
          ),
          promptMessage: 'Explorer: attestation outside Android',
        );
        await _cleanUpScratch(r.code);
        return _expect(BiometricError.notSupported, r.code, r.error,
            successHint: 'This device attested the key (Android 7+).');
      case ErrorTrigger.keyNotFound:
        await api.deleteKeys(keyAlias: KeyAlias.missing.value);
        final r = await api.createSignatureFromBytes(
          payload: secureRandomBytes(32),
          keyAlias: KeyAlias.missing.value,
          promptMessage: 'Explorer: this alias has no key',
        );
        return _expect(BiometricError.keyNotFound, r.code, r.error);
      case ErrorTrigger.userCanceled:
        final r = await api.simplePrompt(
          promptMessage: 'Cancel this prompt to see userCanceled',
        );
        return _expect(BiometricError.userCanceled, r.code, r.error,
            alsoAccepted: {BiometricError.systemCanceled},
            successHint: 'You authenticated instead of cancelling.');
      case ErrorTrigger.lockedOut:
        final r = await api.simplePrompt(
          promptMessage: 'Fail with an unenrolled finger or face',
          config: SimplePromptConfig(allowDeviceCredentials: false),
        );
        return _expect(BiometricError.lockedOut, r.code, r.error,
            alsoAccepted: {BiometricError.lockedOutPermanent},
            successHint: 'Authentication succeeded; keep failing instead.');
      case ErrorTrigger.invalidationCreate:
        final config = CreateKeysConfig(
          signatureType: _signatureType,
          setInvalidatedByBiometricEnrollment: true,
          requireAuthentication: true,
          useDeviceCredentials: false,
          enforceBiometric: false,
          failIfExists: false,
        );
        final r = await api.createKeys(
          keyAlias: KeyAlias.explorerB.value,
          config: config,
          promptMessage: 'Create the key to invalidate',
        );
        state.noteCreateKeysResult(
          alias: KeyAlias.explorerB,
          result: r,
          config: config,
          keyFormat: KeyFormat.base64,
        );
        return _expect(BiometricError.success, r.code, r.error);
      case ErrorTrigger.invalidationSign:
        final r = await api.createSignatureFromBytes(
          payload: secureRandomBytes(32),
          keyAlias: KeyAlias.explorerB.value,
          promptMessage: 'Sign with the key you tried to invalidate',
        );
        return _expect(BiometricError.keyInvalidated, r.code, r.error,
            successHint: 'The key still works: enroll a new fingerprint or '
                'face first (step 2).');
      case ErrorTrigger.invalidationCheck:
        final info = await api.getKeyInfo(
          keyAlias: KeyAlias.explorerB.value,
          checkValidity: true,
        );
        final invalid = info.exists == true && info.isValid == false;
        return TriggerOutcome(
          summary: 'exists: ${info.exists}, isValid: ${info.isValid}'
              '${invalid ? ' — invalidated, as expected.' : ''}',
          asExpected: invalid,
        );
    }
  }

  Future<TriggerOutcome> _keyAlreadyExists() async {
    final alias = KeyAlias.errorsScratch.value;
    final first = await api.createKeys(
      keyAlias: alias,
      config: CreateKeysConfig(
        signatureType: _signatureType,
        requireAuthentication: false,
        failIfExists: false,
      ),
      promptMessage: 'Explorer: create a scratch key',
    );
    if (!isSuccessCode(first.code)) {
      return TriggerOutcome(
        summary: 'Could not create the scratch key '
            '(${first.code?.name ?? 'unknown'}), so there is nothing to '
            'collide with.',
        asExpected: false,
        code: first.code,
        error: first.error,
      );
    }
    final second = await api.createKeys(
      keyAlias: alias,
      config: CreateKeysConfig(
        signatureType: _signatureType,
        requireAuthentication: false,
        failIfExists: true,
      ),
      promptMessage: 'Explorer: create it again with failIfExists',
    );
    await api.deleteKeys(keyAlias: alias);
    return _expect(BiometricError.keyAlreadyExists, second.code, second.error);
  }

  Future<void> _cleanUpScratch(BiometricError? code) async {
    if (isSuccessCode(code)) {
      await api.deleteKeys(keyAlias: KeyAlias.errorsScratch.value);
    }
  }
}
