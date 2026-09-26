import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/bank_client.dart';
import '../client/transaction_payload.dart';
import '../money.dart';
import '../server/models.dart';
import '../widgets/bank_widgets.dart';

/// The bank's decision with its full verification trace.
class ReceiptScreen extends StatelessWidget {
  /// Creates the screen.
  const ReceiptScreen({
    super.key,
    required this.payload,
    required this.result,
    required this.reportedAuthentication,
    this.fault,
  });

  /// The payload the user approved.
  final TransactionPayload payload;

  /// The bank's response.
  final ConfirmResult result;

  /// `authenticationType` from the signature result.
  final AuthenticationType? reportedAuthentication;

  /// A compromised-app fault applied to this request, if any.
  final String? fault;

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final transfer = result.transfer;
    final accepted = result.accepted;
    final auth = describeAuthenticationType(
      reportedAuthentication,
      platform: services.platform,
      silentKey: payload.tier == RiskTier.a,
    );
    return BankScaffold(
      title: 'Receipt',
      body: ListView(
        padding: pagePadding(context),
        children: [
          CapabilityBanner(
            kind: accepted ? StatusKind.success : StatusKind.danger,
            icon: accepted ? Icons.check_circle : Icons.gpp_bad_outlined,
            title: accepted ? 'Transfer sent' : 'Rejected by the bank',
            message: accepted
                ? '${payload.amountText} to ${payload.payee} '
                    '(${payload.txnId}).'
                : result.reason ?? 'The bank rejected the request.',
          ),
          if (fault != null) ...[
            gap,
            CapabilityBanner(
              kind: StatusKind.warning,
              icon: Icons.bug_report_outlined,
              title: 'Fault injected',
              message: '$fault. See which check caught it below.',
            ),
          ],
          gap,
          SectionCard(
            title: 'Summary',
            trailing: TierChip(payload.tier),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                KeyValueRow(
                    label: 'Amount',
                    value: payload.amountText,
                    copyable: false),
                KeyValueRow(
                    label: 'To',
                    value: '${payload.payee} ${payload.payeeAccount}',
                    copyable: false),
                KeyValueRow(
                    label: 'From', value: payload.fromAccount, copyable: false),
                KeyValueRow(
                    label: 'Signed with',
                    value: payload.tier.requiredAlias,
                    copyable: false),
                KeyValueRow(
                  label: 'Reported authentication',
                  value: '${auth.label}. ${auth.reliability}',
                  copyable: false,
                ),
                if (transfer?.anomaly ?? false)
                  const KeyValueRow(
                    label: 'Anomaly',
                    value: 'Flagged for review: the reported method '
                        'contradicts the key\'s policy.',
                    copyable: false,
                    trailing:
                        StatusChip(label: 'Flagged', kind: StatusKind.warning),
                  ),
                if (transfer?.balanceAfterCents != null)
                  KeyValueRow(
                    label: 'Balance after',
                    value: formatCents(transfer!.balanceAfterCents!),
                    copyable: false,
                  ),
              ],
            ),
          ),
          gap,
          SectionCard(
            title: 'Request signature (device_binding)',
            subtitle: 'Checked before the transfer handler runs',
            child: ChecksView(result.requestChecks),
          ),
          gap,
          SectionCard(
            title: 'Transfer approval',
            subtitle: 'Checked against the bytes the bank issued',
            child: ChecksView(result.checks,
                emptyText: 'Not evaluated: the request itself was rejected.'),
          ),
          gap,
          FilledButton(
            key: const ValueKey('receipt-done'),
            onPressed: () =>
                Navigator.of(context).popUntil((route) => route.isFirst),
            child: const Text('Done'),
          ),
        ],
      ),
    );
  }
}
