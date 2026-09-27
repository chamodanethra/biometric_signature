import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/approval_service.dart';
import '../client/bank_client.dart';
import '../money.dart';
import '../server/models.dart';
import '../widgets/bank_widgets.dart';
import 'receipt_screen.dart';
import 'reverify_screen.dart';

/// Shows the decoded payload the bank issued and signs exactly those bytes.
class ApproveScreen extends StatefulWidget {
  /// Creates the screen.
  const ApproveScreen({super.key, required this.prepared});

  /// The bank's prepared transfer.
  final PreparedTransfer prepared;

  @override
  State<ApproveScreen> createState() => _ApproveScreenState();
}

class _ApproveScreenState extends State<ApproveScreen> {
  bool _busy = false;
  ApprovalOutcome? _problem;

  Future<void> _approve() async {
    final services = AppScope.of(context);
    final session = services.session;
    setState(() {
      _busy = true;
      _problem = null;
    });
    final outcome = await services.approvals.approve(
      widget.prepared,
      allowDeviceCredential: session.enrollment?.allowDeviceCredential ?? false,
    );
    if (!mounted) return;
    setState(() => _busy = false);
    switch (outcome) {
      case ApprovalSubmitted(:final result, :final signature, :final fault):
        session.applyConfirm(result);
        await Navigator.of(context).pushReplacement(MaterialPageRoute(
          builder: (_) => ReceiptScreen(
            payload: widget.prepared.payload,
            result: result,
            reportedAuthentication: signature.authenticationType,
            fault: fault,
          ),
        ));
      case ApprovalNeedsReverification(:final reason):
        session.lockApprovals(reason);
        setState(() => _problem = outcome);
      case ApprovalBindingLost(:final reason):
        await session.bindingLost(reason);
        services.navigatorKey.currentState?.popUntil((r) => r.isFirst);
      case ApprovalCancelled():
      case ApprovalFailed():
        setState(() => _problem = outcome);
    }
  }

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final session = services.session;
    final p = widget.prepared.payload;
    final theme = Theme.of(context);
    final account = session.snapshot?.accounts
        .where((a) => a.id == p.fromAccount)
        .firstOrNull;
    final deviceKeyMatches =
        p.deviceKey == session.enrollment?.deviceKeyFingerprint;
    final needsApprovalKey = p.tier != RiskTier.a;
    final locked = needsApprovalKey && session.approvalsLocked;
    return BankScaffold(
      title: 'Review & approve',
      body: ListView(
        padding: pagePadding(context),
        children: [
          const CapabilityBanner(
            icon: Icons.visibility_outlined,
            title: 'What you see is what you sign',
            message: 'Everything below is decoded from the bytes the bank '
                'issued. Approving signs those bytes unchanged; the bank '
                'verifies the signature against its own copy.',
          ),
          gap,
          SectionCard(
            title: 'Transfer',
            subtitle: 'Decoded from the signed bytes',
            trailing: TierChip(p.tier),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(p.amountText,
                    key: const ValueKey('approve-amount'),
                    style: theme.textTheme.displaySmall),
                const SizedBox(height: 8),
                KeyValueRow(
                    label: 'Pay to',
                    value: '${p.payee} ${p.payeeAccount}',
                    copyable: false),
                KeyValueRow(
                    label: 'From',
                    value: account == null
                        ? p.fromAccount
                        : '${p.fromAccount} (${account.name})',
                    copyable: false),
                KeyValueRow(label: 'Reference', value: p.txnId),
                KeyValueRow(
                    label: 'Issued / expires',
                    value: '${formatTime(p.issuedAt)} / '
                        '${formatTime(p.expiresAt)}',
                    copyable: false),
                KeyValueRow(
                  label: 'Bound to device key',
                  value: formatFingerprint(p.deviceKey, maxGroups: 4),
                  copyable: false,
                  trailing: StatusChip(
                    label: deviceKeyMatches ? 'This device' : 'Other device!',
                    kind: deviceKeyMatches
                        ? StatusKind.success
                        : StatusKind.danger,
                  ),
                ),
                KeyValueRow(label: 'Nonce (single use)', value: p.nonce),
              ],
            ),
          ),
          gap,
          SectionCard(
            title: 'How it will be signed',
            child: needsApprovalKey
                ? Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Text('createSignatureFromBytes with '
                          '${KeyAliases.approval}: a biometric prompt. The '
                          'prompt text comes from the app, so it is a '
                          'convenience; the bank\'s guarantee is that the '
                          'signature covers these exact bytes.'),
                      const SizedBox(height: 8),
                      KeyValueRow(
                          label: 'promptMessage (iOS/macOS show only this)',
                          value: p.promptMessage,
                          copyable: false),
                      KeyValueRow(
                          label: 'promptSubtitle (Android)',
                          value: p.promptSubtitle,
                          copyable: false),
                      KeyValueRow(
                          label: 'promptDescription (Android)',
                          value: p.promptDescription,
                          copyable: false),
                      KeyValueRow(
                          label: 'allowDeviceCredentials',
                          value:
                              '${session.enrollment?.allowDeviceCredential ?? false}',
                          copyable: false),
                    ],
                  )
                : Text('createSignatureFromBytes with '
                    '${KeyAliases.deviceBinding}: no prompt'
                    '${services.capabilities.silentKeysPrompt ? ' (Windows Hello still asks)' : ''}. '
                    'This proves the request comes from this device, not '
                    'that you approved it, which is why tier A has a low '
                    'limit.'),
          ),
          gap,
          SectionCard(
            title: 'Signed bytes',
            subtitle: '${p.bytes.length} bytes · sha256 '
                '${p.sha256.substring(0, 16)}…',
            child: MonoBlock(text: p.canonicalText, label: 'Canonical JSON'),
          ),
          if (locked) ...[
            gap,
            _reverifyBanner(context, session.approvalsLockedReason!),
          ],
          if (_problem != null) ...[gap, _problemView(context, _problem!)],
          gap,
          FilledButton.icon(
            key: const ValueKey('approve'),
            onPressed: _busy || locked ? null : _approve,
            icon: _busy
                ? const SizedBox.square(
                    dimension: 18,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : Icon(needsApprovalKey ? Icons.fingerprint : Icons.check),
            label: Text(needsApprovalKey
                ? 'Approve with biometrics'
                : 'Approve (silent device signature)'),
          ),
          const SizedBox(height: 8),
          TextButton(
            onPressed: _busy ? null : () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }

  Widget _reverifyBanner(BuildContext context, String reason) =>
      CapabilityBanner(
        kind: StatusKind.danger,
        icon: Icons.lock_outline,
        title: 'Approvals locked',
        message: '$reason The silent device key still works, so the bank can '
            're-verify you with a one-time code and register a new approval '
            'key.',
        action: FilledButton.tonal(
          key: const ValueKey('go-reverify'),
          onPressed: () => Navigator.of(context).pushReplacement(
            MaterialPageRoute(
              builder: (_) =>
                  ReverifyScreen(reason: 'keyInvalidated', explanation: reason),
            ),
          ),
          child: const Text('Re-verify'),
        ),
      );

  Widget _problemView(BuildContext context, ApprovalOutcome outcome) {
    return switch (outcome) {
      ApprovalCancelled(:final code) => CapabilityBanner(
          kind: StatusKind.warning,
          title: 'Not approved (${code.name})',
          message: 'Nothing was sent. You can approve until '
              '${formatTime(widget.prepared.payload.expiresAt)}.',
        ),
      ApprovalFailed(:final code, :final message) => code == null
          ? CapabilityBanner(
              kind: StatusKind.danger,
              title: 'The bank could not be reached',
              message: message,
            )
          : ErrorBanner(
              guidance: guidanceFor(code),
              rawMessage: message,
              actionLabel: code == BiometricError.lockedOut ||
                      code == BiometricError.lockedOutPermanent
                  ? null
                  : 'Try again',
              onAction: _busy ? null : _approve,
            ),
      ApprovalNeedsReverification(:final code) => Text(
          'The plugin returned ${code.name}.',
          style: Theme.of(context).textTheme.bodySmall,
        ),
      ApprovalSubmitted() || ApprovalBindingLost() => const SizedBox.shrink(),
    };
  }
}
