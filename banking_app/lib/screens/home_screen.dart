import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/bank_client.dart';
import '../client/session.dart';
import '../money.dart';
import '../widgets/bank_widgets.dart';
import 'request_log_screen.dart';
import 'reverify_screen.dart';
import 'security_screen.dart';
import 'transfer_screen.dart';

/// Accounts and recent activity, fetched with silently signed requests.
class HomeScreen extends StatelessWidget {
  /// Creates the screen.
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final session = services.session;
    return ListenableBuilder(
      listenable: Listenable.merge([
        session,
        services.transport.asListenable,
        services.client.faults.asListenable,
      ]),
      builder: (context, _) {
        final snapshot = session.snapshot;
        return BankScaffold(
          title: 'Step-up Banking',
          actions: [
            IconButton(
              icon: const Icon(Icons.receipt_long),
              tooltip: 'Signed request log',
              onPressed: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const RequestLogScreen())),
            ),
            IconButton(
              icon: const Icon(Icons.shield_outlined),
              tooltip: 'Keys & security',
              onPressed: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const SecurityScreen())),
            ),
          ],
          floatingActionButton: snapshot == null
              ? null
              : FloatingActionButton.extended(
                  key: const ValueKey('new-transfer'),
                  onPressed: () => Navigator.of(context).push(MaterialPageRoute(
                      builder: (_) => const TransferScreen())),
                  icon: const Icon(Icons.send),
                  label: const Text('Transfer'),
                ),
          body: RefreshIndicator(
            onRefresh: session.refresh,
            child: ListView(
              physics: const AlwaysScrollableScrollPhysics(),
              padding: pagePadding(context),
              children: [
                ..._banners(context, session),
                _greeting(context, session),
                gap,
                if (snapshot == null)
                  _loadCard(context, session)
                else ...[
                  for (final a in snapshot.accounts)
                    Card(
                      child: ListTile(
                        leading: const Icon(Icons.account_balance_wallet),
                        title: Text(a.name),
                        subtitle: Text('${a.id} · ${maskAccount(a.id)}'),
                        trailing: Text(
                          formatCents(a.balanceCents),
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                      ),
                    ),
                  gap,
                  Text('Recent activity',
                      style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 4),
                  for (final p in snapshot.recent)
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: p.tier == null
                          ? const Icon(Icons.swap_horiz)
                          : TierChip(p.tier!),
                      title: Text(p.description),
                      subtitle: Text('${formatDateTime(p.time)} · '
                          '${p.accountId}${p.txnId == null ? '' : ' · ${p.txnId}'}'),
                      trailing: Text(
                        formatCents(p.amountCents, signed: true),
                        style: TextStyle(
                          color: p.amountCents < 0
                              ? null
                              : context.statusColors.success,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                ],
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _greeting(BuildContext context, BankSession session) {
    final theme = Theme.of(context);
    final snapshot = session.snapshot;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Hi, ${session.enrollment?.customerName.split(' ').first ?? ''}',
            style: theme.textTheme.headlineSmall),
        Text(
          snapshot == null
              ? 'Accounts not loaded yet.'
              : 'Updated ${formatTime(snapshot.fetchedAt)} with a request '
                  'signed silently by device_binding. Pull to refresh.',
          style: theme.textTheme.bodySmall,
        ),
      ],
    );
  }

  Widget _loadCard(BuildContext context, BankSession session) {
    return SectionCard(
      title: 'Load your accounts',
      subtitle: session.silentKeysPrompt
          ? 'Windows Hello will ask you to confirm the signed request.'
          : 'The request is signed silently by device_binding.',
      child: Align(
        alignment: Alignment.centerLeft,
        child: session.refreshing
            ? const CircularProgressIndicator()
            : FilledButton.icon(
                key: const ValueKey('load-accounts'),
                onPressed: session.refresh,
                icon: const Icon(Icons.refresh),
                label: const Text('Load accounts'),
              ),
      ),
    );
  }

  List<Widget> _banners(BuildContext context, BankSession session) {
    final services = AppScope.of(context);
    final snapshot = session.snapshot;
    final registration = session.lastRegistration;
    final error = session.refreshError;
    final banners = <Widget>[
      if (registration != null)
        SectionCard(
          title: 'Keys registered',
          subtitle: 'What the bank verified',
          trailing: IconButton(
            icon: const Icon(Icons.close),
            tooltip: 'Dismiss',
            onPressed: session.dismissRegistration,
          ),
          child: ChecksView(registration.checks),
        ),
      if (session.approvalsLocked)
        CapabilityBanner(
          key: const ValueKey('reverify-banner'),
          kind: StatusKind.danger,
          icon: Icons.lock_outline,
          title: 'Approvals locked',
          message: '${session.approvalsLockedReason} Tier A transfers still '
              'work with the silent device key. Re-verify to register a new '
              'approval key.',
          action: FilledButton.tonal(
            key: const ValueKey('open-reverify'),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute(
                builder: (_) => ReverifyScreen(
                    reason: switch (session.approvalKeyHealth?.status) {
                      KeyHealthStatus.invalidated => 'keyInvalidated',
                      KeyHealthStatus.missing => 'keyNotFound',
                      _ => 'approval key mismatch',
                    },
                    explanation: session.approvalsLockedReason!))),
            child: const Text('Re-verify'),
          ),
        ),
      if (session.silentKeysPrompt)
        const CapabilityBanner(
          kind: StatusKind.warning,
          title: 'Windows Hello prompts for every request',
          message: 'Windows Hello prompts even for the device-binding key, '
              'so background request signing prompts every time. '
              'Auto-refresh is off; pull to refresh.',
        ),
      if (snapshot != null)
        ...() {
          final policy = snapshot.policy;
          final decision =
              policy.evaluate(policy.tierBLimitCents + 1, snapshot.device);
          if (decision.allowed) return const <Widget>[];
          return [
            CapabilityBanner(
              title: 'Capped at tier B',
              message: decision.reason!,
            ),
          ];
        }(),
      if (error != null)
        error.kind == BankErrorKind.signing
            ? ErrorBanner(
                guidance: guidanceFor(error.code),
                rawMessage: error.message,
                actionLabel: 'Retry',
                onAction: session.refresh,
              )
            : CapabilityBanner(
                kind: StatusKind.danger,
                title: error.kind == BankErrorKind.network
                    ? 'The bank could not be reached'
                    : 'The bank rejected the request',
                message: error.message,
                action: FilledButton.tonal(
                    onPressed: session.refresh, child: const Text('Retry')),
              ),
    ];
    final faults = [
      for (final f in services.transport.pendingFaults) f.label,
      if (services.client.faults.alterAmountAfterApproval)
        'compromised app: change the amount after the next approval',
    ];
    if (faults.isNotEmpty) {
      banners.add(CapabilityBanner(
        kind: StatusKind.warning,
        icon: Icons.bug_report_outlined,
        title: 'Faults armed (server console)',
        message: faults.join('\n'),
      ));
    }
    return [
      for (final b in banners) ...[b, gap],
    ];
  }
}
