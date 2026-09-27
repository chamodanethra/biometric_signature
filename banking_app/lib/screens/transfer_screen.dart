import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/bank_client.dart';
import '../money.dart';
import '../server/models.dart';
import '../server/risk_policy.dart';
import '../widgets/bank_widgets.dart';
import 'approve_screen.dart';

/// Enter a transfer; see its risk tier live; ask the bank to prepare it.
class TransferScreen extends StatefulWidget {
  /// Creates the screen.
  const TransferScreen({super.key});

  @override
  State<TransferScreen> createState() => _TransferScreenState();
}

class _TransferScreenState extends State<TransferScreen> {
  final _amount = TextEditingController();
  String? _fromAccount;
  String? _payeeId;
  bool _busy = false;
  BankError? _error;

  @override
  void initState() {
    super.initState();
    _amount.addListener(() => setState(() => _error = null));
  }

  @override
  void dispose() {
    _amount.dispose();
    super.dispose();
  }

  Future<void> _review() async {
    final services = AppScope.of(context);
    final cents = parseAmountToCents(_amount.text);
    if (cents == null || _fromAccount == null || _payeeId == null) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final prepared = await services.client.prepareTransfer(
        fromAccount: _fromAccount!,
        payeeId: _payeeId!,
        amountCents: cents,
      );
      if (!mounted) return;
      await Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => ApproveScreen(prepared: prepared)));
    } on BankError catch (e) {
      if (mounted) setState(() => _error = e);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final snapshot = services.session.snapshot;
    if (snapshot == null) {
      return const BankScaffold(
        title: 'New transfer',
        body: Center(child: Text('Load your accounts first.')),
      );
    }
    _fromAccount ??= snapshot.accounts.first.id;
    _payeeId ??= snapshot.payees.first.id;
    final policy = snapshot.policy;
    final cents = parseAmountToCents(_amount.text);
    final theme = Theme.of(context);
    final examples = [
      4500,
      125000,
      policy.tierBLimitCents + 40000,
    ];
    return BankScaffold(
      title: 'New transfer',
      body: ListView(
        padding: pagePadding(context),
        children: [
          SectionCard(
            title: 'From',
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (final a in snapshot.accounts)
                  ChoiceChip(
                    label: Text('${a.name} ${maskAccount(a.id)} · '
                        '${formatCents(a.balanceCents)}'),
                    selected: _fromAccount == a.id,
                    onSelected: (_) => setState(() => _fromAccount = a.id),
                  ),
              ],
            ),
          ),
          gap,
          SectionCard(
            title: 'To',
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (final p in snapshot.payees)
                  ChoiceChip(
                    label: Text('${p.name} ${p.account}'),
                    selected: _payeeId == p.id,
                    onSelected: (_) => setState(() => _payeeId = p.id),
                  ),
              ],
            ),
          ),
          gap,
          SectionCard(
            title: 'Amount',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                TextField(
                  key: const ValueKey('amount-field'),
                  controller: _amount,
                  keyboardType:
                      const TextInputType.numberWithOptions(decimal: true),
                  decoration: InputDecoration(
                    prefixText: r'$ ',
                    labelText: 'Amount (USD)',
                    errorText: _amount.text.isNotEmpty && cents == null
                        ? 'Enter an amount like 1250 or 1,250.00'
                        : null,
                  ),
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 8,
                  children: [
                    for (final e in examples)
                      ActionChip(
                        label: Text('${formatCents(e)} · tier '
                            '${policy.tierFor(e).label}'),
                        onPressed: () => _amount.text = '${e ~/ 100}.'
                            '${(e % 100).toString().padLeft(2, '0')}',
                      ),
                  ],
                ),
              ],
            ),
          ),
          gap,
          if (cents == null)
            SectionCard(
              title: 'Risk tier',
              subtitle: 'Enter an amount to see what the bank will require',
              child: _TierTable(policy: policy),
            )
          else
            _TierPreview(
                decision: policy.evaluate(cents, snapshot.device),
                policy: policy,
                fetchedAt: snapshot.fetchedAt),
          if (_error != null) ...[
            gap,
            CapabilityBanner(
              kind: StatusKind.danger,
              title: _error!.reasonCode == 'tier'
                  ? 'The bank declined this transfer'
                  : 'Could not prepare the transfer',
              message: _error!.message,
            ),
          ],
          gap,
          FilledButton.icon(
            key: const ValueKey('review-transfer'),
            onPressed: _busy || cents == null || cents <= 0 ? null : _review,
            icon: _busy
                ? const SizedBox.square(
                    dimension: 18,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.arrow_forward),
            label: const Text('Review'),
          ),
          const SizedBox(height: 8),
          Text(
            'Review asks the bank to prepare the transfer (a request signed '
            'silently by device_binding). The bank decides the tier and '
            'returns the exact bytes you will approve.',
            style: theme.textTheme.bodySmall,
          ),
        ],
      ),
    );
  }
}

class _TierPreview extends StatelessWidget {
  const _TierPreview({
    required this.decision,
    required this.policy,
    required this.fetchedAt,
  });

  final TierDecision decision;
  final RiskPolicy policy;
  final DateTime fetchedAt;

  @override
  Widget build(BuildContext context) {
    final tier = decision.tier;
    return SectionCard(
      key: const ValueKey('tier-preview'),
      title: 'Tier ${tier.label} · ${policy.rangeFor(tier)}',
      subtitle: 'Preview from the bank\'s policy as of '
          '${formatTime(fetchedAt)}; the bank decides when you continue.',
      trailing: TierChip(tier),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          KeyValueRow(
              label: 'Requires', value: decision.requirement, copyable: false),
          KeyValueRow(
            label: 'Signed by',
            value: tier == RiskTier.a
                ? '${KeyAliases.deviceBinding} — silently, no prompt'
                : '${KeyAliases.approval} — biometric prompt',
            copyable: false,
          ),
          if (decision.allowed)
            KeyValueRow(
                label: 'Assurance', value: decision.assurance, copyable: false)
          else ...[
            const SizedBox(height: 8),
            CapabilityBanner(
              kind: StatusKind.warning,
              title: 'Not allowed on this device',
              message: decision.reason!,
            ),
          ],
        ],
      ),
    );
  }
}

class _TierTable extends StatelessWidget {
  const _TierTable({required this.policy});

  final RiskPolicy policy;

  @override
  Widget build(BuildContext context) => Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          for (final t in RiskTier.values)
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: TierChip(t),
              title: Text(policy.rangeFor(t)),
              subtitle: Text(policy.requirementFor(t)),
            ),
        ],
      );
}
