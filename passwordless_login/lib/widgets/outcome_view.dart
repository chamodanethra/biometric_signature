import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../client/outcome.dart';

/// Renders a failed [AuthOutcome] with the matching recovery button.
///
/// Each callback is optional; a button only appears when the screen can
/// handle that recovery.
class OutcomeView extends StatelessWidget {
  /// Creates the view.
  const OutcomeView({
    super.key,
    required this.outcome,
    this.onRetry,
    this.onUnlock,
    this.onRebind,
    this.onPreflight,
    this.onReplaceKey,
    this.onViewReport,
  });

  /// The outcome (a [Success] renders nothing).
  final AuthOutcome<Object?> outcome;

  /// "Try again" / "Retry upload".
  final VoidCallback? onRetry;

  /// Unlock biometrics with the device credential (`lockedOutPermanent`).
  final VoidCallback? onUnlock;

  /// Re-bind this device (recovery code).
  final VoidCallback? onRebind;

  /// Open the device check (`passcodeNotSet`, `notEnrolled`, …).
  final VoidCallback? onPreflight;

  /// Delete the key under the alias and continue (`keyAlreadyExists`).
  final VoidCallback? onReplaceKey;

  /// Show the attestation report behind a rejection.
  final VoidCallback? onViewReport;

  @override
  Widget build(BuildContext context) {
    final o = outcome;
    switch (o) {
      case Success():
        return const SizedBox.shrink();
      case Retryable(
          guidance: final guidance?,
          :final rawMessage,
          :final retry
        ):
        return ErrorBanner(
          guidance: guidance,
          rawMessage: rawMessage,
          onAction: onRetry,
          actionLabel: retry == RetryKind.freshChallenge
              ? 'Start again with a fresh challenge'
              : 'Try again',
        );
      case Retryable(:final rawMessage, :final retry):
        final upload = retry == RetryKind.reupload;
        return CapabilityBanner(
          kind: StatusKind.warning,
          icon: Icons.cloud_off,
          title: upload ? 'Upload failed — the key is safe' : 'Network error',
          message: upload
              ? 'The key was created on this device, but the server never '
                  'received it (${rawMessage ?? 'no response'}). Retrying '
                  'reads the public key and attestation chain back with '
                  'getKeyInfo and re-sends them; the server keeps the '
                  'challenge until it expires.'
              : rawMessage ?? 'The server could not be reached.',
          action: onRetry == null
              ? null
              : FilledButton.tonal(
                  key: const Key('retry'),
                  onPressed: onRetry,
                  child: Text(upload ? 'Retry upload' : 'Try again'),
                ),
        );
      case Blocked(:final guidance, :final rawMessage):
        final (label, action) = switch (guidance.code) {
          BiometricError.lockedOutPermanent => (
              'Unlock with PIN / passcode',
              onUnlock
            ),
          BiometricError.keyAlreadyExists => (
              'Delete the old key and continue',
              onReplaceKey
            ),
          BiometricError.passcodeNotSet ||
          BiometricError.notEnrolled ||
          BiometricError.notAvailable =>
            ('Open device check', onPreflight),
          _ => (null, null),
        };
        return ErrorBanner(
          guidance: guidance,
          rawMessage: rawMessage,
          onAction: action,
          actionLabel: label,
        );
      case NeedsRebind(:final reason):
        return CapabilityBanner(
          kind: StatusKind.danger,
          icon: Icons.key_off,
          title: 'This device needs a new key',
          message: '$reason\n\nRe-bind uses your recovery code: the server '
              'verifies a fresh attestation for a new key and retires this '
              'one. Without the code, create a new account.',
          action: onRebind == null
              ? null
              : FilledButton(
                  key: const Key('rebind'),
                  onPressed: onRebind,
                  child: const Text('Re-bind this device'),
                ),
        );
      case Rejected(:final reason, :final report):
        return CapabilityBanner(
          kind: StatusKind.danger,
          icon: Icons.gpp_bad_outlined,
          title: 'Rejected by the server',
          message: reason,
          action: report == null || onViewReport == null
              ? null
              : OutlinedButton(
                  onPressed: onViewReport,
                  child: const Text('View attestation report'),
                ),
        );
    }
  }
}
