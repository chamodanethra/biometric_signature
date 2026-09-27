import 'dart:convert';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';

import '../models/sealed_item.dart';
import 'vault_key_manager.dart';

/// Result of [RevealService.reveal].
sealed class RevealOutcome {
  const RevealOutcome();
}

/// The secret, decrypted.
final class Revealed extends RevealOutcome {
  /// Creates the outcome.
  const Revealed({
    required this.plaintext,
    required this.authenticationType,
    required this.viaEnvelope,
  });

  /// The plaintext. It now lives in Dart memory until it is dropped and
  /// garbage-collected; Dart strings cannot be wiped.
  final String plaintext;

  /// How the user authenticated (see `describeAuthenticationType`).
  final AuthenticationType? authenticationType;

  /// Whether `decrypt()` returned an envelope data key that was then used
  /// in Dart.
  final bool viaEnvelope;
}

/// `decrypt()` returned an error code.
final class RevealFailed extends RevealOutcome {
  /// Creates the outcome.
  const RevealFailed({required this.code, this.message, this.health});

  /// The plugin's error code.
  final BiometricError code;

  /// The plugin's message.
  final String? message;

  /// `getKeyInfo(checkValidity: true)` after an unexpected failure, to tell
  /// a broken key from a broken ciphertext.
  final KeyHealth? health;

  /// The key is gone for good (invalidated or missing).
  bool get keyUnusable =>
      code == BiometricError.keyInvalidated ||
      code == BiometricError.keyNotFound ||
      (health != null && !health!.isHealthy);

  /// The key is fine, so the ciphertext itself could not be decrypted.
  bool get ciphertextRejected => health?.isHealthy == true;
}

/// `decrypt()` succeeded, but the envelope content failed its AES-GCM
/// integrity check: it was modified after sealing.
final class RevealIntegrityFailure extends RevealOutcome {
  /// Creates the outcome.
  const RevealIntegrityFailure(this.reason, this.authenticationType);

  /// What failed.
  final String reason;

  /// The (successful) authentication that unwrapped the data key.
  final AuthenticationType? authenticationType;
}

/// Decrypts vault items with the plugin — the cryptographic gate.
class RevealService {
  /// Creates the service.
  const RevealService(this.api, {this.alias = VaultKeyManager.alias});

  /// The plugin.
  final BiometricSignature api;

  /// Key alias.
  final String alias;

  /// Codes after which the key's health is checked with `getKeyInfo`.
  static const Set<BiometricError> _unexpected = {
    BiometricError.unknown,
    BiometricError.invalidInput,
  };

  /// Encodes the base64 [payload] as [format] expects.
  static String encodePayload(String payload, PayloadFormat format) =>
      switch (format) {
        PayloadFormat.hex => toHex(base64.decode(payload)),
        PayloadFormat.base64 || PayloadFormat.raw => payload,
      };

  /// Decrypts [item] (prompting for biometrics).
  ///
  /// [promptTitle] is shown in the prompt; pass `null` to keep the title
  /// out of the system dialog. [allowDeviceCredentials] should match how
  /// the key was created (Android only; iOS uses the key's own policy).
  Future<RevealOutcome> reveal(
    SealedItem item, {
    PayloadFormat format = PayloadFormat.base64,
    bool allowDeviceCredentials = false,
    String? promptTitle,
  }) async {
    final result = await api.decrypt(
      payload: encodePayload(item.devicePayloadBase64, format),
      payloadFormat: format,
      keyAlias: alias,
      // iOS/macOS show only this message.
      promptMessage:
          promptTitle == null ? 'Reveal a vault item' : 'Reveal "$promptTitle"',
      // Android-only prompt texts and PIN fallback.
      config: DecryptConfig(
        promptSubtitle: promptTitle ?? 'Secure Vault',
        promptDescription: item.format == SealFormat.envelope
            ? "Unwraps this item's data key with your vault key. The key "
                'never leaves secure hardware.'
            : 'Decrypts this item with your vault key. The key never leaves '
                'secure hardware.',
        cancelButtonText: 'Keep hidden',
        allowDeviceCredentials: allowDeviceCredentials,
      ),
    );
    final text = result.decryptedData;
    if (result.code != BiometricError.success || text == null) {
      final code = result.code ?? BiometricError.unknown;
      final health =
          _unexpected.contains(code) ? await probeKey(api, alias: alias) : null;
      return RevealFailed(code: code, message: result.error, health: health);
    }
    if (item.format == SealFormat.direct) {
      return Revealed(
        plaintext: text,
        authenticationType: result.authenticationType,
        viaEnvelope: false,
      );
    }
    try {
      final bytes = openEnvelope(text, item.envelope!);
      return Revealed(
        plaintext: utf8.decode(bytes),
        authenticationType: result.authenticationType,
        viaEnvelope: true,
      );
    } on AesGcmAuthenticationException {
      return RevealIntegrityFailure(
        'The data key unwrapped correctly, but the AES-GCM tag of the '
        'content did not verify: the content was modified after sealing.',
        result.authenticationType,
      );
    } on FormatException catch (e) {
      return RevealIntegrityFailure(e.message, result.authenticationType);
    }
  }
}
