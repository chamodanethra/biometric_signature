import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/bank_client.dart';
import '../money.dart';
import '../widgets/bank_widgets.dart';

/// Every request the app signed with `device_binding`, and the bank's
/// verdict on it.
class RequestLogScreen extends StatelessWidget {
  /// Creates the screen.
  const RequestLogScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final log = services.client.requestLog;
    return BankScaffold(
      title: 'Signed requests',
      actions: [
        IconButton(
          icon: const Icon(Icons.delete_sweep_outlined),
          tooltip: 'Clear',
          onPressed: log.clear,
        ),
      ],
      body: ListenableBuilder(
        listenable: log.asListenable,
        builder: (context, _) {
          final entries = log.entries.reversed.toList();
          return ListView(
            padding: pagePadding(context),
            children: [
              CapabilityBanner(
                icon: Icons.phonelink_lock,
                title: 'Silent request signing',
                message: 'Each call is signed by device_binding with '
                    'createSignature over METHOD\\nPATH\\nTIMESTAMP\\n'
                    'sha256(body)\\nrequestId. The bank rejects timestamps '
                    'outside ±${services.server.policy.maxClockSkewSeconds} s, '
                    'reused request ids and bad signatures. '
                    '${services.capabilities.silentKeysPrompt ? 'On Windows, Windows Hello prompts for each one.' : 'No prompt is shown: the key proves the device, not the user.'}',
              ),
              gap,
              if (entries.isEmpty)
                const Padding(
                  padding: EdgeInsets.all(24),
                  child: Center(child: Text('No signed requests yet.')),
                ),
              for (final e in entries) _EntryTile(entry: e),
            ],
          );
        },
      ),
    );
  }
}

class _EntryTile extends StatelessWidget {
  const _EntryTile({required this.entry});

  final RequestLogEntry entry;

  @override
  Widget build(BuildContext context) {
    final (label, kind) = switch (entry.status) {
      RequestStatus.signing => ('Signing', StatusKind.neutral),
      RequestStatus.sent => ('Sent', StatusKind.neutral),
      RequestStatus.verified => ('Verified', StatusKind.success),
      RequestStatus.rejected => ('Rejected', StatusKind.danger),
      RequestStatus.networkError => ('Network error', StatusKind.warning),
      RequestStatus.signingFailed => ('Not signed', StatusKind.danger),
    };
    final ms = entry.signingTime?.inMilliseconds;
    return Card(
      child: ExpansionTile(
        title: Text('${entry.route.method} ${entry.route.path}',
            style: monospaceStyle(context,
                base: Theme.of(context).textTheme.bodyMedium)),
        subtitle: Text('${formatTime(entry.time)} · id '
            '${entry.requestId.substring(0, 8)}…'
            '${ms == null ? '' : ' · signed in $ms ms'}'
            '${entry.detail == null ? '' : '\n${entry.detail}'}'),
        trailing: StatusChip(label: label, kind: kind),
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
        expandedCrossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          MonoBlock(label: 'Signed string', text: entry.canonical),
          const SizedBox(height: 8),
          KeyValueRow(label: 'Signature', value: entry.signature ?? '—'),
          KeyValueRow(
            label: 'authenticationType',
            value: entry.authenticationType?.name ?? '—',
            copyable: false,
          ),
          const SizedBox(height: 8),
          ChecksView(entry.serverChecks,
              emptyText: 'No verdict from the bank.'),
        ],
      ),
    );
  }
}
