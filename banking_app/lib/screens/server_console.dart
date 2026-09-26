import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../client/bank_client.dart';
import '../client/transaction_payload.dart';
import '../money.dart';
import '../server/request_signing.dart';
import '../server/risk_policy.dart';
import '../services.dart';
import '../widgets/bank_widgets.dart';

/// The bank server console: records, audit, wire, policy and faults.
List<DevConsoleTab> buildServerConsoleTabs(AppServices services) => [
      DevConsoleTab(
        label: 'Records',
        icon: Icons.storage_outlined,
        builder: (_) => _RecordsTab(services: services),
      ),
      DevConsoleTab(
        label: 'Audit',
        icon: Icons.history,
        builder: (_) => AuditLogView(log: services.server.audit),
      ),
      DevConsoleTab(
        label: 'Wire',
        icon: Icons.swap_vert,
        builder: (_) => WireLogView(log: services.transport.log),
      ),
      DevConsoleTab(
        label: 'Policy',
        icon: Icons.policy_outlined,
        builder: (_) => _PolicyTab(services: services),
      ),
      DevConsoleTab(
        label: 'Faults',
        icon: Icons.bug_report_outlined,
        builder: (_) => _FaultsTab(services: services),
      ),
    ];

const EdgeInsets _tabPadding = EdgeInsets.fromLTRB(16, 12, 16, 32);

class _RecordsTab extends StatelessWidget {
  const _RecordsTab({required this.services});

  final AppServices services;

  @override
  Widget build(BuildContext context) {
    final server = services.server;
    return ListenableBuilder(
      listenable: Listenable.merge([
        server.asListenable,
        server.ledger.asListenable,
        server.outbox.asListenable,
      ]),
      builder: (context, _) {
        final theme = Theme.of(context);
        final pending = server.pendingTransfers;
        final sms = server.outbox.messages.reversed.take(3).toList();
        return ListView(
          padding: _tabPadding,
          children: [
            const Text('Demo mock server: records live in SharedPreferences '
                '(server.*), challenges and replay caches in memory. No TLS, '
                'no rate limits, no revocation checks.'),
            gap,
            Text('Accounts', style: theme.textTheme.titleSmall),
            for (final a in server.ledger.accounts)
              KeyValueRow(
                  label: '${a.id} ${a.name}',
                  value: formatCents(a.balanceCents),
                  copyable: false),
            gap,
            Text('Devices (${server.devices.length})',
                style: theme.textTheme.titleSmall),
            if (server.devices.isEmpty) const Text('None bound.'),
            for (final d in server.devices.toList().reversed)
              Card(
                child: ExpansionTile(
                  title: Text('${d.deviceId} · ${d.platform.label}'),
                  subtitle: Text('Bound ${formatDateTime(d.enrolledAt)}'),
                  trailing: StatusChip(
                    label: d.status.name,
                    kind: d.isActive ? StatusKind.success : StatusKind.neutral,
                  ),
                  childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                  expandedCrossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    for (final k in [d.deviceKey, ...d.approvalKeys])
                      KeyValueRow(
                        label: k.alias,
                        value:
                            '${formatFingerprint(k.fingerprint, maxGroups: 4)}'
                            '\n${k.description} · ${k.authPolicySummary}'
                            '${k.isActive ? '' : '\nrevoked: ${k.revokeReason}'}',
                        copyable: false,
                        trailing: k.isActive
                            ? TrustChip(k.trustTier)
                            : const StatusChip(label: 'Revoked'),
                      ),
                  ],
                ),
              ),
            gap,
            Text('Pending approvals (${pending.length})',
                style: theme.textTheme.titleSmall),
            for (final p in pending)
              KeyValueRow(
                label: p.txnId,
                value: '${formatCents(p.amountCents)} to ${p.payee.name} · '
                    'tier ${p.tier.label} · expires '
                    '${formatTime(p.expiresAt)}',
                copyable: false,
              ),
            gap,
            Text('Transfers (${server.transfers.length})',
                style: theme.textTheme.titleSmall),
            for (final t in server.transfers.reversed.take(20))
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: TierChip(t.tier),
                title: Text('${t.txnId} · ${formatCents(t.amountCents)} → '
                    '${t.payee}'),
                subtitle: Text('${formatTime(t.decidedAt)} · signed by '
                    '${t.signer} · reported ${t.authenticationType ?? 'none'}'
                    '${t.reason == null ? '' : '\n${t.reason}'}'),
                trailing: Wrap(
                  spacing: 4,
                  direction: Axis.vertical,
                  crossAxisAlignment: WrapCrossAlignment.end,
                  children: [
                    StatusChip(
                      label: t.status.name,
                      kind: t.accepted ? StatusKind.success : StatusKind.danger,
                    ),
                    if (t.anomaly)
                      const StatusChip(
                          label: 'anomaly', kind: StatusKind.warning),
                  ],
                ),
              ),
            gap,
            Text('Simulated SMS outbox', style: theme.textTheme.titleSmall),
            if (sms.isEmpty) const Text('Nothing sent.'),
            for (final m in sms)
              KeyValueRow(
                  label: '${formatTime(m.sentAt)} → ${m.to}',
                  value: m.text,
                  copyable: false),
          ],
        );
      },
    );
  }
}

class _PolicyTab extends StatelessWidget {
  const _PolicyTab({required this.services});

  final AppServices services;

  Future<void> _update(RiskPolicy policy) async {
    await services.server.updatePolicy(policy);
    await services.session.autoRefresh();
  }

  Widget _choice(
    BuildContext context, {
    required String title,
    required int value,
    required List<(int, String)> options,
    required ValueChanged<int> onChanged,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 6),
          SegmentedButton<int>(
            showSelectedIcon: false,
            segments: [
              for (final (v, label) in options)
                ButtonSegment(value: v, label: Text(label)),
            ],
            selected: {value},
            onSelectionChanged: (s) => onChanged(s.first),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final server = services.server;
    return ListenableBuilder(
      listenable: server.asListenable,
      builder: (context, _) {
        final p = server.policy;
        return ListView(
          padding: _tabPadding,
          children: [
            const Text('The bank\'s risk policy (risk_policy.dart). Changes '
                'apply to the next prepare/confirm; the app refreshes its '
                'tier preview (except on Windows).'),
            gap,
            _choice(context,
                title: 'Tier A limit (silent device signature)',
                value: p.tierALimitCents,
                options: const [
                  (5000, r'$50'),
                  (10000, r'$100'),
                  (25000, r'$250')
                ],
                onChanged: (v) => _update(p.copyWith(tierALimitCents: v))),
            _choice(context,
                title: 'Tier B limit (biometric approval)',
                value: p.tierBLimitCents,
                options: const [
                  (100000, r'$1,000'),
                  (200000, r'$2,000'),
                  (500000, r'$5,000')
                ],
                onChanged: (v) => _update(p.copyWith(tierBLimitCents: v))),
            SwitchListTile(
              key: const ValueKey('policy-require-attested'),
              contentPadding: EdgeInsets.zero,
              value: p.requireAttestedBiometricOnlyForTierC,
              onChanged: (v) =>
                  _update(p.copyWith(requireAttestedBiometricOnlyForTierC: v)),
              title:
                  const Text('Require attested biometric-only key for tier C'),
              subtitle: const Text('On: only an Android approval key whose '
                  'attestation shows hardware-enforced userAuthType 2 '
                  '(biometric) and no noAuthRequired qualifies; iOS, macOS '
                  'and Windows are capped at tier B. Off: a key declared '
                  'biometric-only is accepted — declared, unverified.'),
            ),
            gap,
            _choice(context,
                title: 'Request timestamp window',
                value: p.maxClockSkewSeconds,
                options: const [(30, '±30 s'), (60, '±60 s'), (300, '±5 min')],
                onChanged: (v) => _update(p.copyWith(maxClockSkewSeconds: v))),
            _choice(context,
                title: 'Approval window (payload expiry)',
                value: p.approvalTtlSeconds,
                options: const [(30, '30 s'), (120, '2 min'), (300, '5 min')],
                onChanged: (v) => _update(p.copyWith(approvalTtlSeconds: v))),
            OutlinedButton(
              onPressed: () => _update(const RiskPolicy()),
              child: const Text('Restore defaults'),
            ),
          ],
        );
      },
    );
  }
}

class _FaultsTab extends StatefulWidget {
  const _FaultsTab({required this.services});

  final AppServices services;

  @override
  State<_FaultsTab> createState() => _FaultsTabState();
}

class _FaultsTabState extends State<_FaultsTab> {
  String? _last;

  AppServices get _s => widget.services;

  void _note(String text) => setState(() => _last = text);

  Future<void> _showResult(String title, ConfirmResult result) async {
    _note('$title: ${result.accepted ? 'accepted' : 'rejected'}'
        '${result.reason == null ? '' : ' — ${result.reason}'}');
    await showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: SizedBox(
          width: 480,
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(result.accepted
                    ? 'Accepted?! That should not happen.'
                    : 'Rejected: ${result.reason ?? ''}'),
                const SizedBox(height: 8),
                ChecksView([...result.requestChecks, ...result.checks]),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Close')),
        ],
      ),
    );
  }

  Future<void> _replay() async {
    try {
      final response = await _s.transport.replayLast(BankRoutes.confirm.path);
      if (!mounted) return;
      await _showResult('Replayed the captured confirm',
          BankClient.parseConfirmResponse(response));
    } on Object catch (e) {
      _note('Replay failed: $e');
    }
  }

  Future<void> _resubmit() async {
    try {
      final result = await _s.client.resubmitLastConfirm();
      if (!mounted) return;
      await _showResult('Re-submitted the last approval', result);
    } on BankError catch (e) {
      _note('Re-submit failed: ${e.message}');
    }
  }

  Future<void> _reset() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Reset demo?'),
        content: const Text('Calls deleteAllKeys(), clears the client and '
            'server stores and reseeds the accounts. You will bind the '
            'device again.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: const Text('Reset')),
        ],
      ),
    );
    if (ok ?? false) await _s.resetDemo();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListenableBuilder(
      listenable: Listenable.merge([
        _s.transport.asListenable,
        _s.client.faults.asListenable,
      ]),
      builder: (context, _) {
        final pending = [
          for (final f in _s.transport.pendingFaults) f.label,
          if (_s.client.faults.alterAmountAfterApproval)
            'compromised app: change the amount after the next approval',
        ];
        final skew = _s.clientClock.skew.inSeconds;
        return ListView(
          padding: _tabPadding,
          children: [
            if (_last != null) ...[
              CapabilityBanner(title: 'Last result', message: _last!),
              gap,
            ],
            Text('Network attacker (between the app and the bank)',
                style: theme.textTheme.titleSmall),
            const Text('Can read, change and resend traffic, but has no '
                'keys.'),
            const SizedBox(height: 6),
            Wrap(spacing: 8, runSpacing: 8, children: [
              OutlinedButton(
                key: const ValueKey('fault-tamper'),
                onPressed: () {
                  _s.transport.tamper(BankRoutes.confirm.path, 'body.payload',
                      TransactionPayload.tamperAmount(900000));
                  _note('Armed: the next confirm\'s payload gets +\$9,000. '
                      'Expect "request signature mismatch".');
                },
                child: const Text('Tamper amount on next confirm'),
              ),
              OutlinedButton(
                onPressed: _s.transport.canReplay(BankRoutes.confirm.path)
                    ? _replay
                    : null,
                child: const Text('Replay last confirm'),
              ),
            ]),
            gap,
            Text(
                'Compromised app (can use the silent key, not your '
                'biometric key)',
                style: theme.textTheme.titleSmall),
            const Text('Code inside the app can sign with device_binding at '
                'any time — that is why tier A is capped.'),
            const SizedBox(height: 6),
            Wrap(spacing: 8, runSpacing: 8, children: [
              OutlinedButton(
                key: const ValueKey('fault-alter'),
                onPressed: () {
                  _s.client.faults.alterAmountAfterApproval = true;
                  _note('Armed: after your next approval, the app changes '
                      'the amount (+\$9,000) before sending it.');
                },
                child: const Text('Change amount after approval'),
              ),
              OutlinedButton(
                onPressed: _s.client.canResubmitLastConfirm ? _resubmit : null,
                child: const Text('Re-submit last approval'),
              ),
            ]),
            gap,
            Text('Environment', style: theme.textTheme.titleSmall),
            const SizedBox(height: 6),
            Text('Device clock skew: ${skew >= 0 ? '+' : ''}$skew s'),
            const SizedBox(height: 6),
            SegmentedButton<int>(
              showSelectedIcon: false,
              segments: const [
                ButtonSegment(value: -300, label: Text('−5 min')),
                ButtonSegment(value: -90, label: Text('−90 s')),
                ButtonSegment(value: 0, label: Text('0')),
                ButtonSegment(value: 90, label: Text('+90 s')),
                ButtonSegment(value: 300, label: Text('+5 min')),
              ],
              selected: {skew},
              onSelectionChanged: (s) {
                _s.clientClock.skew = Duration(seconds: s.first);
                _note('Device clock skew set to ${s.first} s. Pull to '
                    'refresh to see the ±'
                    '${_s.server.policy.maxClockSkewSeconds} s check.');
              },
            ),
            const SizedBox(height: 8),
            OutlinedButton(
              onPressed: () {
                _s.transport.failNext('*');
                _note('Armed: the next request fails in transit.');
              },
              child: const Text('Fail next request'),
            ),
            gap,
            Text('Armed faults', style: theme.textTheme.titleSmall),
            if (pending.isEmpty) const Text('None.'),
            for (final f in pending) Text('• $f'),
            if (pending.isNotEmpty)
              Align(
                alignment: Alignment.centerLeft,
                child: TextButton(
                  onPressed: () {
                    _s.transport.clearFaults();
                    _s.client.faults.clear();
                    _note('Faults cleared.');
                  },
                  child: const Text('Clear faults'),
                ),
              ),
            const Divider(height: 32),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                backgroundColor: theme.colorScheme.error,
                foregroundColor: theme.colorScheme.onError,
              ),
              onPressed: _reset,
              icon: const Icon(Icons.restart_alt),
              label: const Text('Reset demo'),
            ),
          ],
        );
      },
    );
  }
}
