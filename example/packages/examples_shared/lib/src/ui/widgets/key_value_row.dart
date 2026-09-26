import 'package:flutter/material.dart';

import '../theme.dart';
import 'copy.dart';

/// A label/value row with selectable text and an optional copy button.
/// Stacks vertically on narrow widths.
class KeyValueRow extends StatelessWidget {
  /// Creates a row.
  const KeyValueRow({
    super.key,
    required this.label,
    required this.value,
    this.monospace = false,
    this.copyable = true,
    this.trailing,
  });

  /// Label.
  final String label;

  /// Value.
  final String value;

  /// Render the value in a monospace font.
  final bool monospace;

  /// Show a copy button.
  final bool copyable;

  /// Extra widget after the value.
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final labelWidget = Text(
      label,
      style: theme.textTheme.labelMedium
          ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
    );
    final valueWidget = SelectableText(
      value.isEmpty ? '—' : value,
      style: monospace
          ? monospaceStyle(context, base: theme.textTheme.bodyMedium)
          : theme.textTheme.bodyMedium,
    );
    final actions = [
      if (trailing != null) trailing!,
      if (copyable && value.isNotEmpty)
        IconButton(
          icon: const Icon(Icons.copy, size: 18),
          tooltip: 'Copy $label',
          visualDensity: VisualDensity.compact,
          onPressed: () => copyToClipboard(context, value, what: label),
        ),
    ];
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: LayoutBuilder(builder: (context, constraints) {
        if (constraints.maxWidth < 420) {
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    labelWidget,
                    const SizedBox(height: 2),
                    valueWidget
                  ],
                ),
              ),
              ...actions,
            ],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
              width: 160,
              child: Padding(
                padding: const EdgeInsets.only(top: 2, right: 12),
                child: labelWidget,
              ),
            ),
            Expanded(child: valueWidget),
            ...actions,
          ],
        );
      }),
    );
  }
}
