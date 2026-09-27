import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:flutter/widgets.dart';

import 'controller_base.dart';
import 'key_alias.dart';
import 'result_fields.dart';

/// Attestation challenge lengths offered on the Keys screen. 0 means no
/// challenge; 129 is one byte over the limit and returns `invalidInput`.
const List<int> attestationChallengeLengths = [0, 32, 128, 129];

/// Keys screen: `createKeys` with every argument.
class KeysController extends ExplorerController {
  /// Creates the controller.
  KeysController(super.state)
      : signatureType = state.capabilities.supportsEcKeys
            ? SignatureType.ecdsa
            : SignatureType.rsa;

  /// Operation id for [create].
  static const String createOp = 'createKeys';

  /// `CreateKeysConfig.signatureType`.
  SignatureType signatureType;

  /// `keyFormat`.
  KeyFormat keyFormat = KeyFormat.base64;

  /// `CreateKeysConfig.enforceBiometric`.
  bool enforceBiometric = false;

  /// `CreateKeysConfig.setInvalidatedByBiometricEnrollment`.
  bool setInvalidatedByBiometricEnrollment = true;

  /// `CreateKeysConfig.useDeviceCredentials`.
  bool useDeviceCredentials = false;

  /// `CreateKeysConfig.enableDecryption`.
  bool enableDecryption = false;

  /// `CreateKeysConfig.failIfExists`.
  bool failIfExists = false;

  /// `CreateKeysConfig.requireAuthentication`.
  bool requireAuthentication = true;

  /// Length of the random attestation challenge (0 = none).
  int attestationLength = 0;

  /// `promptMessage`.
  final TextEditingController promptMessage =
      TextEditingController(text: 'Create a key for the Explorer');

  /// `CreateKeysConfig.promptSubtitle`.
  final TextEditingController promptSubtitle = TextEditingController();

  /// `CreateKeysConfig.promptDescription`.
  final TextEditingController promptDescription = TextEditingController();

  /// `CreateKeysConfig.cancelButtonText`.
  final TextEditingController cancelButtonText = TextEditingController();

  /// Last result.
  KeyCreationResult? result;

  /// Alias of [result].
  KeyAlias? resultAlias;

  /// Config sent for [result].
  CreateKeysConfig? resultConfig;

  /// Local inspection of [result]'s attestation chain.
  AttestationReport? report;

  /// Whether [report] is being computed.
  bool verifyingAttestation = false;

  /// Builds the config for the current form, with [challenge].
  CreateKeysConfig buildConfig({Uint8List? challenge}) => CreateKeysConfig(
        signatureType: signatureType,
        enforceBiometric: enforceBiometric,
        setInvalidatedByBiometricEnrollment:
            setInvalidatedByBiometricEnrollment,
        useDeviceCredentials: useDeviceCredentials,
        enableDecryption: enableDecryption,
        promptSubtitle: ExplorerController.optionalText(promptSubtitle),
        promptDescription: ExplorerController.optionalText(promptDescription),
        cancelButtonText: ExplorerController.optionalText(cancelButtonText),
        failIfExists: failIfExists,
        requireAuthentication: requireAuthentication,
        attestationChallenge: challenge,
      );

  /// Applies a preset combination of options.
  void applyPreset(KeyPreset preset) {
    update(() {
      final ec = state.capabilities.supportsEcKeys;
      requireAuthentication = true;
      enableDecryption = false;
      attestationLength = 0;
      switch (preset) {
        case KeyPreset.biometricEc:
          signatureType = ec ? SignatureType.ecdsa : SignatureType.rsa;
        case KeyPreset.ecWithDecryption:
          signatureType = ec ? SignatureType.ecdsa : SignatureType.rsa;
          enableDecryption = true;
        case KeyPreset.rsaWithDecryption:
          signatureType = SignatureType.rsa;
          enableDecryption = true;
        case KeyPreset.silentDeviceKey:
          signatureType = ec ? SignatureType.ecdsa : SignatureType.rsa;
          requireAuthentication = false;
          state.selectAlias(KeyAlias.explorerSilent);
        case KeyPreset.attested:
          signatureType = ec ? SignatureType.ecdsa : SignatureType.rsa;
          // Outside Android this demonstrates notSupported; Windows has no
          // attestation controls at all.
          attestationLength = state.platform == DevicePlatform.windows ? 0 : 32;
      }
    });
  }

  /// Calls `createKeys` for the selected alias and, when an attestation
  /// chain comes back, inspects it locally.
  Future<void> create() => run(createOp, () async {
        final alias = state.selectedAlias;
        final challenge = attestationLength == 0
            ? null
            : secureRandomBytes(attestationLength);
        final config = buildConfig(challenge: challenge);
        result = null;
        report = null;
        notifyListeners();
        final r = await api.createKeys(
          keyAlias: alias.value,
          config: config,
          keyFormat: keyFormat,
          promptMessage: ExplorerController.optionalText(promptMessage),
        );
        result = r;
        resultAlias = alias;
        resultConfig = config;
        state.noteCreateKeysResult(
          alias: alias,
          result: r,
          config: config,
          keyFormat: keyFormat,
        );
        final chain = r.attestationCertificateChain;
        final publicKey = r.publicKey;
        if (isSuccessCode(r.code) &&
            chain != null &&
            chain.isNotEmpty &&
            challenge != null &&
            publicKey != null) {
          verifyingAttestation = true;
          notifyListeners();
          try {
            report = await state.inspectAttestation(
              chain: chain,
              expectedChallenge: challenge,
              expectedPublicKey: publicKey,
            );
          } finally {
            verifyingAttestation = false;
          }
        }
      });

  @override
  void dispose() {
    promptMessage.dispose();
    promptSubtitle.dispose();
    promptDescription.dispose();
    cancelButtonText.dispose();
    super.dispose();
  }
}

/// Option presets on the Keys screen.
enum KeyPreset {
  /// EC signing key that needs biometrics.
  biometricEc('Biometric EC'),

  /// EC key that can also decrypt (Android hybrid / Apple ECIES).
  ecWithDecryption('EC + decryption'),

  /// RSA key that signs and decrypts (OAEP).
  rsaWithDecryption('RSA + decryption'),

  /// Non-interactive device key (`requireAuthentication: false`).
  silentDeviceKey('Silent device key'),

  /// EC key with a 32-byte attestation challenge (Android).
  attested('Attested (Android)');

  const KeyPreset(this.label);

  /// Chip label.
  final String label;
}
