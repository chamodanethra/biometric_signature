import 'package:flutter/material.dart';

import '../theme.dart';
import 'copy.dart';

/// A selectable monospace block (keys, signatures, JSON) with a copy button.
class MonoBlock extends StatelessWidget {
  /// Creates a block.
  const MonoBlock({
    super.key,
    required this.text,
    this.label,
    this.copyable = true,
    this.wrap = true,
    this.maxHeight,
  });

  /// Content.
  final String text;

  /// Optional caption above the block.
  final String? label;

  /// Show a copy button.
  final bool copyable;

  /// Wrap long lines (otherwise scroll horizontally).
  final bool wrap;

  /// Limits the height; the block scrolls vertically beyond it.
  final double? maxHeight;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    Widget content = SelectableText(text, style: monospaceStyle(context));
    if (!wrap) {
      content = SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: content,
      );
    }
    if (maxHeight != null) {
      content = ConstrainedBox(
        constraints: BoxConstraints(maxHeight: maxHeight!),
        child: SingleChildScrollView(child: content),
      );
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (label != null || copyable)
          Row(
            children: [
              if (label != null)
                Expanded(
                  child: Text(
                    label!,
                    style: theme.textTheme.labelMedium
                        ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                  ),
                )
              else
                const Spacer(),
              if (copyable)
                IconButton(
                  icon: const Icon(Icons.copy, size: 18),
                  tooltip: 'Copy ${label ?? 'text'}',
                  visualDensity: VisualDensity.compact,
                  onPressed: () =>
                      copyToClipboard(context, text, what: label ?? 'Text'),
                ),
            ],
          ),
        Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: theme.colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
          ),
          child: content,
        ),
      ],
    );
  }
}
