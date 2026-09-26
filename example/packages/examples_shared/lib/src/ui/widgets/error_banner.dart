import 'package:flutter/material.dart';

import '../error_guidance.dart';
import '../theme.dart';

/// A default button label for [action], or `null` for [RecoveryAction.none].
String? recoveryActionLabel(RecoveryAction action) => switch (action) {
      RecoveryAction.none => null,
      RecoveryAction.retry => 'Try again',
      RecoveryAction.retryLater => 'Try again later',
      RecoveryAction.enrollBiometrics => 'How to enroll',
      RecoveryAction.setDeviceLock => 'How to set a screen lock',
      RecoveryAction.recreateKey => 'Register again',
      RecoveryAction.useDeviceCredential => 'Unlock with PIN / passcode',
      RecoveryAction.updateOs => 'Check for updates',
      RecoveryAction.chooseDifferentAlias => 'Use existing key',
      RecoveryAction.fixInput => 'Details',
      RecoveryAction.unsupportedOnDevice => 'Continue without',
    };

/// Shows [ErrorGuidance] with an optional recovery button.
class ErrorBanner extends StatelessWidget {
  /// Creates a banner.
  const ErrorBanner({
    super.key,
    required this.guidance,
    this.rawMessage,
    this.onAction,
    this.actionLabel,
    this.onDismiss,
  });

  /// The guidance to show.
  final ErrorGuidance guidance;

  /// The plugin's `error` string, shown small for developers.
  final String? rawMessage;

  /// Called by the action button; no button when `null`.
  final VoidCallback? onAction;

  /// Button label (defaults to [recoveryActionLabel]).
  final String? actionLabel;

  /// Shows a close button when set.
  final VoidCallback? onDismiss;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final kind = guidance.isTransient ? StatusKind.warning : StatusKind.danger;
    final colors = context.statusColors;
    final fg = colors.onContainer(kind, theme.colorScheme);
    final label = actionLabel ?? recoveryActionLabel(guidance.action);
    return Semantics(
      container: true,
      liveRegion: true,
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: colors.container(kind, theme.colorScheme),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(statusIconFor(kind), color: fg),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '${guidance.title} (${guidance.code.name})',
                    style: theme.textTheme.titleSmall?.copyWith(color: fg),
                  ),
                  const SizedBox(height: 4),
                  Text(guidance.message,
                      style: theme.textTheme.bodyMedium?.copyWith(color: fg)),
                  if (rawMessage != null && rawMessage!.isNotEmpty) ...[
                    const SizedBox(height: 4),
                    SelectableText(
                      rawMessage!,
                      style: monospaceStyle(context).copyWith(color: fg),
                    ),
                  ],
                  if (onAction != null && label != null) ...[
                    const SizedBox(height: 8),
                    FilledButton.tonal(
                      onPressed: onAction,
                      child: Text(label),
                    ),
                  ],
                ],
              ),
            ),
            if (onDismiss != null)
              IconButton(
                icon: Icon(Icons.close, color: fg),
                tooltip: 'Dismiss',
                onPressed: onDismiss,
              ),
          ],
        ),
      ),
    );
  }
}
