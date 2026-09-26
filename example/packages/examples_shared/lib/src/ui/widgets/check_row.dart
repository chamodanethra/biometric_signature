import 'package:flutter/material.dart';

import '../../attestation/attestation_report.dart';
import '../theme.dart';

/// One pass / fail / warn / info line with an explanation.
class CheckRow extends StatelessWidget {
  /// Creates a row.
  const CheckRow({
    super.key,
    required this.kind,
    required this.title,
    this.detail,
  });

  /// A row for an [AttestationCheck].
  factory CheckRow.fromCheck(AttestationCheck check, {Key? key}) => CheckRow(
        key: key,
        kind: statusKindForCheck(check.status),
        title: check.title,
        detail: check.detail,
      );

  /// Status.
  final StatusKind kind;

  /// Title.
  final String title;

  /// Explanation.
  final String? detail;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final color = context.statusColors.accent(kind, theme.colorScheme);
    return Semantics(
      label: '${kind.name}: $title',
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(statusIconFor(kind), color: color, size: 20),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title,
                      style: theme.textTheme.bodyMedium
                          ?.copyWith(fontWeight: FontWeight.w600)),
                  if (detail != null && detail!.isNotEmpty)
                    SelectableText(
                      detail!,
                      style: theme.textTheme.bodySmall
                          ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
