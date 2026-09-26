import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/ui.dart';

import 'accounts.dart';

/// What the UI should do after a client operation.
///
/// Every plugin error code and server rejection is mapped to exactly one of
/// these, so screens never inspect raw codes.
sealed class AuthOutcome<T> {
  const AuthOutcome();

  /// Re-types a non-[Success] outcome (for passing failures up).
  AuthOutcome<R> castFailure<R>() => switch (this) {
        Success() => throw StateError('castFailure on Success'),
        NeedsRebind(:final reason, :final account, :final health) =>
          NeedsRebind<R>(reason, account: account, health: health),
        Retryable(:final guidance, :final rawMessage, :final retry) =>
          Retryable<R>(guidance, rawMessage: rawMessage, retry: retry),
        Blocked(:final guidance, :final rawMessage) =>
          Blocked<R>(guidance, rawMessage: rawMessage),
        Rejected(:final reason, :final code, :final report, :final checks) =>
          Rejected<R>(reason, code: code, report: report, checks: checks),
      };
}

/// It worked.
final class Success<T> extends AuthOutcome<T> {
  /// Creates the outcome.
  const Success(this.value);

  /// The result.
  final T value;
}

/// This device's key for the account can no longer sign in — it is
/// missing, invalidated by a biometric enrollment change, or retired by the
/// server. Re-bind with the recovery code, or register a new account.
final class NeedsRebind<T> extends AuthOutcome<T> {
  /// Creates the outcome.
  const NeedsRebind(this.reason, {this.account, this.health});

  /// Why.
  final String reason;

  /// The affected local account, if known.
  final LocalAccount? account;

  /// The key probe that confirmed it, if one ran.
  final KeyHealth? health;
}

/// How to retry a [Retryable] operation.
enum RetryKind {
  /// Run the same operation again (e.g. after a cancelled prompt).
  again,

  /// Start over with a fresh server challenge (e.g. the keystore could not
  /// attest right now: `notAvailable`).
  freshChallenge,

  /// Re-send the registration: the key exists, only the upload failed. The
  /// chain and public key are read back with `getKeyInfo`.
  reupload,
}

/// A transient problem: offer to try again.
final class Retryable<T> extends AuthOutcome<T> {
  /// Creates the outcome. [guidance] is `null` for network failures.
  const Retryable(this.guidance,
      {this.rawMessage, this.retry = RetryKind.again});

  /// Guidance for the plugin error, or `null` when the network failed.
  final ErrorGuidance? guidance;

  /// The plugin's or transport's message.
  final String? rawMessage;

  /// What "try again" means.
  final RetryKind retry;
}

/// The user has to do something first (set a screen lock, enroll a
/// biometric, unlock with the device credential, confirm replacing a key).
final class Blocked<T> extends AuthOutcome<T> {
  /// Creates the outcome.
  const Blocked(this.guidance, {this.rawMessage});

  /// What to do.
  final ErrorGuidance guidance;

  /// The plugin's message.
  final String? rawMessage;

  /// The plugin error code.
  BiometricError get code => guidance.code;
}

/// The server refused.
final class Rejected<T> extends AuthOutcome<T> {
  /// Creates the outcome.
  const Rejected(this.reason, {this.code, this.report, this.checks = const []});

  /// The server's explanation.
  final String reason;

  /// The server's error code (see `ServerErrors`), if any.
  final String? code;

  /// The attestation report behind a rejected registration.
  final AttestationReport? report;

  /// The verification steps behind a rejected signed request.
  final List<AttestationCheck> checks;
}
