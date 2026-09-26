import 'package:flutter/material.dart';

import '../theme.dart';

/// Explains a platform limitation or a notable behaviour.
class CapabilityBanner extends StatelessWidget {
  /// Creates a banner.
  const CapabilityBanner({
    super.key,
    required this.title,
    required this.message,
    this.kind = StatusKind.info,
    this.icon,
    this.action,
  });

  /// Title.
  final String title;

  /// Explanation.
  final String message;

  /// Colouring.
  final StatusKind kind;

  /// Icon (defaults to one matching [kind]).
  final IconData? icon;

  /// Optional action (e.g. a button).
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = context.statusColors;
    final fg = colors.onContainer(kind, theme.colorScheme);
    return Semantics(
      container: true,
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: colors.container(kind, theme.colorScheme),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon ?? statusIconFor(kind), color: fg),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title,
                      style: theme.textTheme.titleSmall?.copyWith(color: fg)),
                  const SizedBox(height: 4),
                  Text(message,
                      style: theme.textTheme.bodyMedium?.copyWith(color: fg)),
                  if (action != null) ...[
                    const SizedBox(height: 8),
                    action!,
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
