import 'package:flutter/material.dart';

import '../../attestation/attestation_report.dart';
import '../theme.dart';

/// A small coloured pill with an optional icon.
class StatusChip extends StatelessWidget {
  /// Creates a chip.
  const StatusChip({
    super.key,
    required this.label,
    this.kind = StatusKind.neutral,
    this.icon,
    this.showIcon = true,
  });

  /// A chip for an attestation [CheckStatus].
  factory StatusChip.forCheck(CheckStatus status, {Key? key, String? label}) =>
      StatusChip(
        key: key,
        label: label ?? status.name.toUpperCase(),
        kind: statusKindForCheck(status),
      );

  /// Text.
  final String label;

  /// Colour scheme.
  final StatusKind kind;

  /// Icon (defaults to one matching [kind]).
  final IconData? icon;

  /// Whether to show the icon.
  final bool showIcon;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final colors = context.statusColors;
    final fg = colors.onContainer(kind, scheme);
    return Semantics(
      label: '$label, ${kind.name}',
      excludeSemantics: true,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: ShapeDecoration(
          color: colors.container(kind, scheme),
          shape: const StadiumBorder(),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (showIcon) ...[
              Icon(icon ?? statusIconFor(kind), size: 14, color: fg),
              const SizedBox(width: 4),
            ],
            Flexible(
              child: Text(
                label,
                overflow: TextOverflow.ellipsis,
                style: Theme.of(context)
                    .textTheme
                    .labelSmall
                    ?.copyWith(color: fg, fontWeight: FontWeight.w600),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
