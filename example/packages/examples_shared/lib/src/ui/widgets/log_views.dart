import 'dart:convert';

import 'package:flutter/material.dart';

import '../../server/audit_log.dart';
import '../../server/transport.dart';
import '../observable_listenable.dart';
import '../theme.dart';
import 'mono_block.dart';
import 'status_chip.dart';

const JsonEncoder _pretty = JsonEncoder.withIndent('  ');

String _time(DateTime t) {
  final l = t.toLocal();
  String two(int v) => v.toString().padLeft(2, '0');
  return '${two(l.hour)}:${two(l.minute)}:${two(l.second)}';
}

/// Lists [MockTransport] round trips, newest first, with expandable JSON.
class WireLogView extends StatelessWidget {
  /// Creates the view. It is a scroll view; set [shrinkWrap] to embed it
  /// in another one.
  const WireLogView({
    super.key,
    required this.log,
    this.shrinkWrap = false,
    this.emptyText = 'No requests yet.',
  });

  /// The log.
  final WireLog log;

  /// Passed to the [ListView].
  final bool shrinkWrap;

  /// Shown when the log is empty.
  final String emptyText;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: log.asListenable,
      builder: (context, _) {
        final entries = log.entries.reversed.toList();
        if (entries.isEmpty) {
          return Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Text(emptyText),
            ),
          );
        }
        return ListView.builder(
          shrinkWrap: shrinkWrap,
          physics: shrinkWrap ? const NeverScrollableScrollPhysics() : null,
          itemCount: entries.length,
          itemBuilder: (context, i) => _WireTile(entry: entries[i]),
        );
      },
    );
  }
}

class _WireTile extends StatelessWidget {
  const _WireTile({required this.entry});

  final WireEntry entry;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ok = entry.response?['ok'];
    final StatusKind kind;
    final String status;
    if (entry.failed) {
      kind = StatusKind.danger;
      status = 'ERROR';
    } else if (entry.response == null) {
      kind = StatusKind.neutral;
      status = '…';
    } else if (ok == false) {
      kind = StatusKind.warning;
      status = 'REJECTED';
    } else {
      kind = StatusKind.success;
      status = 'OK';
    }
    return ExpansionTile(
      title: Text(entry.route,
          style: monospaceStyle(context, base: theme.textTheme.bodyMedium)),
      subtitle: Text(
        '${_time(entry.timestamp)}'
        '${entry.elapsed == null ? '' : ' · ${entry.elapsed!.inMilliseconds} ms'}'
        '${entry.faults.isEmpty ? '' : ' · ${entry.faults.join(', ')}'}',
        style: theme.textTheme.bodySmall,
      ),
      trailing: StatusChip(label: status, kind: kind),
      childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
      children: [
        MonoBlock(label: 'Request', text: _pretty.convert(entry.request)),
        const SizedBox(height: 8),
        if (entry.error != null)
          MonoBlock(label: 'Error', text: entry.error!)
        else if (entry.response != null)
          MonoBlock(label: 'Response', text: _pretty.convert(entry.response)),
      ],
    );
  }
}

/// Lists [AuditLog] entries, newest first.
class AuditLogView extends StatelessWidget {
  /// Creates the view. It is a scroll view; set [shrinkWrap] to embed it.
  const AuditLogView({
    super.key,
    required this.log,
    this.shrinkWrap = false,
    this.emptyText = 'Nothing recorded yet.',
  });

  /// The log.
  final AuditLog log;

  /// Passed to the [ListView].
  final bool shrinkWrap;

  /// Shown when the log is empty.
  final String emptyText;

  static StatusKind _kind(AuditSeverity s) => switch (s) {
        AuditSeverity.info => StatusKind.info,
        AuditSeverity.success => StatusKind.success,
        AuditSeverity.warning => StatusKind.warning,
        AuditSeverity.danger => StatusKind.danger,
      };

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: log.asListenable,
      builder: (context, _) {
        final entries = log.entries.reversed.toList();
        if (entries.isEmpty) {
          return Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Text(emptyText),
            ),
          );
        }
        final theme = Theme.of(context);
        return ListView.separated(
          shrinkWrap: shrinkWrap,
          physics: shrinkWrap ? const NeverScrollableScrollPhysics() : null,
          itemCount: entries.length,
          separatorBuilder: (_, __) => const Divider(height: 1),
          itemBuilder: (context, i) {
            final e = entries[i];
            final kind = _kind(e.severity);
            return ListTile(
              leading: Icon(statusIconFor(kind),
                  color: context.statusColors.accent(kind, theme.colorScheme)),
              title: Text(e.event),
              subtitle: Text(
                '${_time(e.time)} · ${e.actor}'
                '${e.detail.isEmpty ? '' : '\n${e.detail}'}',
              ),
              isThreeLine: e.detail.isNotEmpty,
            );
          },
        );
      },
    );
  }
}
