import 'dart:convert';
import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:flutter/widgets.dart';

import 'controller_base.dart';
import 'key_alias.dart';
import 'result_fields.dart';

/// Which signing method the Sign screen calls.
enum SignMode {
  /// `createSignature` (UTF-8 text payload).
  text,

  /// `createSignatureFromBytes` (raw bytes payload).
  bytes,
}

/// Where the bytes payload comes from.
enum BytesSource {
  /// A fresh random 32-byte nonce.
  randomNonce,

  /// Hex typed by the user.
  hex,
}

/// One local verification check.
class VerifyCheck {
  /// Creates a check.
  const VerifyCheck({
    required this.title,
    required this.outcome,
    required this.expectValid,
  });

  /// What was checked.
  final String title;

  /// The verifier's outcome.
  final VerifyOutcome outcome;

  /// Whether a valid signature was expected (false for the tamper check).
  final bool expectValid;

  /// Whether the outcome is what a correct implementation produces.
  bool get asExpected => outcome.isValid == expectValid;
}

/// Sign screen: `createSignature` and `createSignatureFromBytes`.
class SignController extends ExplorerController {
  /// Creates the controller.
  SignController(super.state);

  /// Operation id for [sign].
  static const String signOp = 'sign';

  /// Method to call.
  SignMode mode = SignMode.bytes;

  /// Payload for [SignMode.text].
  final TextEditingController textPayload = TextEditingController(
      text: 'Hello from the Biometric Signature Explorer');

  /// Source of the payload for [SignMode.bytes].
  BytesSource bytesSource = BytesSource.randomNonce;

  /// The current random nonce.
  Uint8List nonce = secureRandomBytes(32);

  /// Hex payload for [BytesSource.hex].
  final TextEditingController hexPayload =
      TextEditingController(text: '00112233445566778899aabbccddeeff');

  /// `signatureFormat`.
  SignatureFormat signatureFormat = SignatureFormat.base64;

  /// `keyFormat` for the returned public key.
  KeyFormat keyFormat = KeyFormat.base64;

  /// `CreateSignatureConfig.allowDeviceCredentials`.
  bool allowDeviceCredentials = false;

  /// `promptMessage`.
  final TextEditingController promptMessage =
      TextEditingController(text: 'Sign with your Explorer key');

  /// `CreateSignatureConfig.promptSubtitle`.
  final TextEditingController promptSubtitle = TextEditingController();

  /// `CreateSignatureConfig.promptDescription`.
  final TextEditingController promptDescription = TextEditingController();

  /// `CreateSignatureConfig.cancelButtonText`.
  final TextEditingController cancelButtonText = TextEditingController();

  /// Last result.
  SignatureResult? result;

  /// Alias of [result].
  KeyAlias? resultAlias;

  /// Method used for [result].
  SignMode? resultMode;

  /// Signature format requested for [result].
  SignatureFormat? resultFormat;

  /// The exact bytes that were signed.
  Uint8List? signedMessage;

  /// Local verification of [result] (after [verify]).
  List<VerifyCheck>? verification;

  /// Replaces the nonce.
  void regenerateNonce() => update(() => nonce = secureRandomBytes(32));

  /// Error for an invalid [hexPayload], or `null`.
  String? get hexError {
    if (bytesSource != BytesSource.hex) return null;
    try {
      fromHex(hexPayload.text);
      return null;
    } on FormatException catch (e) {
      return e.message;
    }
  }

  /// The bytes payload, or `null` when the hex is invalid. An empty hex
  /// field gives an empty payload (the plugin answers `invalidInput`).
  Uint8List? get bytesPayload {
    if (bytesSource == BytesSource.randomNonce) return nonce;
    try {
      return fromHex(hexPayload.text);
    } on FormatException {
      return null;
    }
  }

  /// Whether the form can be submitted.
  bool get canSign => mode == SignMode.text || bytesPayload != null;

  CreateSignatureConfig _config() => CreateSignatureConfig(
        promptSubtitle: ExplorerController.optionalText(promptSubtitle),
        promptDescription: ExplorerController.optionalText(promptDescription),
        cancelButtonText: ExplorerController.optionalText(cancelButtonText),
        allowDeviceCredentials: allowDeviceCredentials,
      );

  /// Signs with the selected alias.
  Future<void> sign() => run(signOp, () async {
        final alias = state.selectedAlias;
        final prompt = ExplorerController.optionalText(promptMessage);
        result = null;
        verification = null;
        notifyListeners();
        final SignatureResult r;
        final Uint8List message;
        if (mode == SignMode.text) {
          final text = textPayload.text;
          message = Uint8List.fromList(utf8.encode(text));
          r = await api.createSignature(
            payload: text,
            keyAlias: alias.value,
            config: _config(),
            signatureFormat: signatureFormat,
            keyFormat: keyFormat,
            promptMessage: prompt,
          );
        } else {
          final bytes = bytesPayload;
          if (bytes == null) throw const FormatException('Invalid hex payload');
          message = Uint8List.fromList(bytes);
          r = await api.createSignatureFromBytes(
            payload: message,
            keyAlias: alias.value,
            config: _config(),
            signatureFormat: signatureFormat,
            keyFormat: keyFormat,
            promptMessage: prompt,
          );
        }
        result = r;
        resultAlias = alias;
        resultMode = mode;
        resultFormat = signatureFormat;
        signedMessage = message;
        // A nonce is single-use: the next signature gets a fresh one.
        if (mode == SignMode.bytes &&
            bytesSource == BytesSource.randomNonce &&
            isSuccessCode(r.code)) {
          nonce = secureRandomBytes(32);
        }
      });

  /// The raw signature bytes of [result].
  Uint8List? get signatureBytes {
    final r = result;
    if (r == null) return null;
    if (r.signatureBytes != null) return r.signatureBytes;
    final sig = r.signature;
    if (sig == null) return null;
    try {
      return resultFormat == SignatureFormat.hex
          ? fromHex(sig)
          : base64.decode(sig);
    } on FormatException {
      return null;
    }
  }

  /// Verifies [result] locally: against the key returned with the
  /// signature, against the key recorded at createKeys, and with a
  /// tampered message (which must fail).
  void verify() {
    final r = result;
    final message = signedMessage;
    final signature = signatureBytes;
    if (r == null || message == null || signature == null) return;
    final checks = <VerifyCheck>[];
    final returnedKey = r.publicKey;
    if (returnedKey != null) {
      checks.add(VerifyCheck(
        title: 'Against SignatureResult.publicKey',
        outcome: verifySignature(
          publicKey: returnedKey,
          message: message,
          signature: signature,
        ),
        expectValid: true,
      ));
    }
    final record = resultAlias == null ? null : state.recordFor(resultAlias!);
    final registered = record?.result.publicKey;
    if (registered != null) {
      checks.add(VerifyCheck(
        title: 'Against the key createKeys returned (what a server stores)',
        outcome: verifySignature(
          publicKey: registered,
          message: message,
          signature: signature,
        ),
        expectValid: true,
      ));
    }
    final key = returnedKey ?? registered;
    if (key != null && message.isNotEmpty) {
      final tampered = Uint8List.fromList(message);
      tampered[0] ^= 0x01;
      checks.add(VerifyCheck(
        title: 'Tampered message (one bit flipped) is rejected',
        outcome: verifySignature(
          publicKey: key,
          message: tampered,
          signature: signature,
        ),
        expectValid: false,
      ));
    }
    update(() => verification = checks);
  }

  @override
  void dispose() {
    textPayload.dispose();
    hexPayload.dispose();
    promptMessage.dispose();
    promptSubtitle.dispose();
    promptDescription.dispose();
    cancelButtonText.dispose();
    super.dispose();
  }
}
