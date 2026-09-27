/// Signing the exact bytes the bank issued, with the key the tier requires.
library;

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';

import '../server/models.dart';
import 'bank_client.dart';
import 'transaction_payload.dart';

/// The outcome of [ApprovalService.approve].
sealed class ApprovalOutcome {
  const ApprovalOutcome();
}

/// Signed and sent; the bank accepted or rejected it (see [result]).
final class ApprovalSubmitted extends ApprovalOutcome {
  /// Creates the outcome.
  const ApprovalSubmitted(this.result, this.signature, {this.fault});

  /// The bank's decision and trace.
  final ConfirmResult result;

  /// The plugin's signature result (for `authenticationType`).
  final SignatureResult signature;

  /// A compromised-app fault that changed the request, if any.
  final String? fault;
}

/// The approval key is invalidated or missing: re-verify.
final class ApprovalNeedsReverification extends ApprovalOutcome {
  /// Creates the outcome.
  const ApprovalNeedsReverification(this.code, this.reason);

  /// `keyInvalidated`, `keyNotFound` or the code that led to the probe.
  final BiometricError code;

  /// Explanation.
  final String reason;
}

/// The device-binding key is gone: bind the device again.
final class ApprovalBindingLost extends ApprovalOutcome {
  /// Creates the outcome.
  const ApprovalBindingLost(this.reason);

  /// Explanation.
  final String reason;
}

/// The user dismissed the prompt.
final class ApprovalCancelled extends ApprovalOutcome {
  /// Creates the outcome.
  const ApprovalCancelled(this.code);

  /// `userCanceled` or `systemCanceled`.
  final BiometricError code;
}

/// Anything else (lockout, network, …).
final class ApprovalFailed extends ApprovalOutcome {
  /// Creates the outcome.
  const ApprovalFailed(this.message, {this.code});

  /// Explanation.
  final String message;

  /// Plugin error code, if the plugin failed.
  final BiometricError? code;
}

/// Approves prepared transfers.
class ApprovalService {
  /// Creates the service.
  ApprovalService({required this.api, required this.client});

  /// The plugin.
  final BiometricSignature api;

  /// Bank client.
  final BankClient client;

  /// Signs [prepared]'s payload bytes and confirms with the bank.
  ///
  /// Tier A signs silently with `device_binding`; tiers B and C sign with
  /// `txn_approval`, which shows the biometric prompt with the amount and
  /// payee. [allowDeviceCredential] must match how the approval key was
  /// created (a biometric-only key cannot be unlocked with a PIN).
  Future<ApprovalOutcome> approve(
    PreparedTransfer prepared, {
    required bool allowDeviceCredential,
  }) async {
    final p = prepared.payload;
    final alias = p.tier.requiredAlias;
    final SignatureResult sig;
    if (p.tier == RiskTier.a) {
      sig = await api.createSignatureFromBytes(
        payload: p.bytes,
        keyAlias: KeyAliases.deviceBinding,
        // Only Windows Hello shows a prompt for this key.
        promptMessage: p.promptMessage,
      );
    } else {
      sig = await api.createSignatureFromBytes(
        payload: p.bytes,
        keyAlias: KeyAliases.approval,
        // iOS and macOS show only promptMessage, so it carries the amount.
        promptMessage: p.promptMessage,
        config: CreateSignatureConfig(
          promptSubtitle: p.promptSubtitle,
          promptDescription: p.promptDescription,
          cancelButtonText: "Don't approve",
          allowDeviceCredentials: allowDeviceCredential,
        ),
      );
    }
    final signature = sig.signature;
    if (sig.code != BiometricError.success || signature == null) {
      return _classifyFailure(alias, sig);
    }

    var bytes = p.bytes;
    var sent = signature;
    String? fault;
    if (client.faults.takeAlterAmount()) {
      // Compromised app: change the amount after the user approved. It can
      // re-sign with the silent key (tier A), but it cannot produce a new
      // biometric signature without the user.
      bytes = TransactionPayload.withAmountChanged(p.bytes, 900000);
      fault = 'Compromised app changed the amount after approval';
      if (p.tier == RiskTier.a) {
        final resigned = await api.createSignatureFromBytes(
            payload: bytes, keyAlias: KeyAliases.deviceBinding);
        if (resigned.signature != null) {
          sent = resigned.signature!;
          fault = '$fault and re-signed it with the silent key';
        }
      }
    }

    try {
      final result = await client.confirmTransfer(
        txnId: p.txnId,
        payload: bytes,
        signature: sent,
        signer: alias,
        authenticationType: sig.authenticationType,
      );
      return ApprovalSubmitted(result, sig, fault: fault);
    } on BankError catch (e) {
      if (e.kind == BankErrorKind.signing &&
          e.code == BiometricError.keyNotFound) {
        return const ApprovalBindingLost(
            'The device-binding key is missing, so the app cannot sign '
            'requests to the bank.');
      }
      return ApprovalFailed(e.message, code: e.code);
    }
  }

  Future<ApprovalOutcome> _classifyFailure(
      String alias, SignatureResult sig) async {
    final code = sig.code ?? BiometricError.unknown;
    if (code == BiometricError.userCanceled ||
        code == BiometricError.systemCanceled) {
      return ApprovalCancelled(code);
    }
    if (alias == KeyAliases.approval &&
        (code == BiometricError.keyInvalidated ||
            code == BiometricError.keyNotFound)) {
      return ApprovalNeedsReverification(
        code,
        code == BiometricError.keyInvalidated
            ? 'Your approval key was invalidated: a fingerprint or face was '
                'added or removed on this device.'
            : 'Your approval key is missing on this device.',
      );
    }
    if (alias == KeyAliases.deviceBinding &&
        code == BiometricError.keyNotFound) {
      return const ApprovalBindingLost(
          'The device-binding key is missing on this device.');
    }
    // Defence in depth: an unexpected error may hide an unusable key.
    if (alias == KeyAliases.approval) {
      final health = await probeKey(api, alias: alias);
      if (!health.isHealthy) {
        return ApprovalNeedsReverification(code, health.summary);
      }
    }
    return ApprovalFailed(sig.error ?? guidanceFor(code).message, code: code);
  }
}
