import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../state/call_log.dart';

/// The call log: every plugin call, newest first, with arguments, result
/// fields and "Copy as Dart".
class CallLogView extends StatelessWidget {
  /// Creates the view.
  const CallLogView({super.key, required this.log});

  /// The log.
  final CallLog log;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: log,
      builder: (context, _) {
        final entries = log.entries.reversed.toList();
        return Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 8, 0),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      '${entries.length} call${entries.length == 1 ? '' : 's'}'
                      ' · newest first',
                      style: Theme.of(context).textTheme.labelLarge,
                    ),
                  ),
                  TextButton.icon(
                    onPressed: entries.isEmpty ? null : log.clear,
                    icon: const Icon(Icons.delete_sweep_outlined),
                    label: const Text('Clear'),
                  ),
                ],
              ),
            ),
            Expanded(
              child: entries.isEmpty
                  ? const Center(
                      child: Padding(
                        padding: EdgeInsets.all(24),
                        child: Text('No plugin calls yet. Every call made by '
                            'any screen appears here.'),
                      ),
                    )
                  : ListView.builder(
                      itemCount: entries.length,
                      itemBuilder: (context, i) =>
                          CallLogTile(entry: entries[i]),
                    ),
            ),
          ],
        );
      },
    );
  }
}

/// One call in the log.
class CallLogTile extends StatelessWidget {
  /// Creates the tile.
  const CallLogTile({super.key, required this.entry});

  /// The entry.
  final CallLogEntry entry;

  StatusKind get _kind => switch (entry.outcome) {
        CallOutcome.success => StatusKind.success,
        CallOutcome.transientError => StatusKind.warning,
        CallOutcome.error || CallOutcome.exception => StatusKind.danger,
      };

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final t = entry.startedAt.toLocal();
    String two(int v) => v.toString().padLeft(2, '0');
    final time = '${two(t.hour)}:${two(t.minute)}:${two(t.second)}';
    return ExpansionTile(
      key: ValueKey('calllog.${entry.id}'),
      leading: Icon(statusIconFor(_kind),
          color: context.statusColors.accent(_kind, theme.colorScheme)),
      title: Text(
        entry.method,
        style: monospaceStyle(context, base: theme.textTheme.titleSmall),
      ),
      subtitle: Text(
        '#${entry.id} · $time · ${entry.duration.inMilliseconds} ms · '
        '${entry.outcomeLabel}',
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
      expandedCrossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const _Heading('Arguments'),
        if (entry.arguments.isEmpty)
          const Text('(none)')
        else
          for (final (name, value) in entry.arguments)
            KeyValueRow(label: name, value: value, copyable: false),
        _Heading(entry.exception != null ? 'Exception' : 'Result'),
        if (entry.exception != null)
          SelectableText(entry.exception!,
              style: monospaceStyle(context)
                  .copyWith(color: context.statusColors.danger))
        else
          for (final f in entry.fields)
            KeyValueRow(
              label: f.name,
              value: f.preview(240),
              monospace: f.monospace,
              copyable: false,
            ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            FilledButton.tonalIcon(
              key: ValueKey('calllog.${entry.id}.dart'),
              onPressed: () =>
                  copyToClipboard(context, entry.snippet, what: 'Dart snippet'),
              icon: const Icon(Icons.code),
              label: const Text('Copy as Dart'),
            ),
            OutlinedButton.icon(
              onPressed: () =>
                  copyToClipboard(context, entry.toText(), what: 'Result'),
              icon: const Icon(Icons.copy),
              label: const Text('Copy result'),
            ),
          ],
        ),
      ],
    );
  }
}

class _Heading extends StatelessWidget {
  const _Heading(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(top: 8, bottom: 2),
      child: Text(text,
          style: theme.textTheme.labelLarge
              ?.copyWith(color: theme.colorScheme.primary)),
    );
  }
}
