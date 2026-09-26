import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../client/auth_client.dart';
import '../widgets/app_scaffold.dart';
import '../widgets/labels.dart';

/// The server's attestation report for a key — after registration (with
/// the one-time recovery code), after a rejection, or from the records.
class AttestationReportScreen extends StatelessWidget {
  /// Creates the screen.
  const AttestationReportScreen({
    super.key,
    required this.report,
    this.registration,
    this.rejected = false,
  });

  /// The report.
  final AttestationReport report;

  /// The registration that produced it, if it just happened.
  final Registration? registration;

  /// Whether the server rejected this key.
  final bool rejected;

  @override
  Widget build(BuildContext context) {
    final reg = registration;
    return AppScaffold(
      title: reg == null
          ? 'Attestation report'
          : reg.isRecovery
              ? 'Device re-bound'
              : 'Account created',
      body: PageList(children: [
        if (reg != null) _RegisteredCard(registration: reg),
        if (reg != null) _RecoveryCodeCard(code: reg.recoveryCode),
        if (reg != null)
          FilledButton(
            key: const Key('report-done'),
            onPressed: () =>
                Navigator.of(context).popUntil((route) => route.isFirst),
            child: const Text('I saved the code — continue'),
          ),
        if (rejected)
          const CapabilityBanner(
            kind: StatusKind.danger,
            title: 'Registration rejected',
            message: 'The server refused this key, so the app deleted it '
                '(deleteKeys). The failing checks are marked below.',
          ),
        CapabilityBanner(
          kind: statusKindForTier(report.trustTier),
          icon: Icons.verified_user_outlined,
          title: 'Trust tier: ${report.trustTier.label}',
          message: tierExplanation(report.trustTier),
        ),
        AttestationReportView(report: report),
      ]),
    );
  }
}

class _RegisteredCard extends StatelessWidget {
  const _RegisteredCard({required this.registration});

  final Registration registration;

  @override
  Widget build(BuildContext context) {
    final a = registration.account;
    return SectionCard(
      title: registration.isRecovery
          ? 'New key bound to ${a.username}'
          : 'Welcome, ${a.username}',
      subtitle: 'What the server stored',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          KeyValueRow(label: 'userId', value: a.userId, monospace: true),
          KeyValueRow(
              label: 'deviceKeyId', value: a.deviceKeyId, monospace: true),
          KeyValueRow(label: 'Key alias', value: a.alias, monospace: true),
          KeyValueRow(
            label: 'Public key SHA-256',
            value: formatFingerprint(a.publicKeyFingerprint, maxGroups: 8),
            monospace: true,
            copyable: false,
          ),
          if (registration.superseded.isNotEmpty)
            KeyValueRow(
              label: 'Retired keys',
              value: registration.superseded.join(', '),
              monospace: true,
            ),
        ],
      ),
    );
  }
}

class _RecoveryCodeCard extends StatelessWidget {
  const _RecoveryCodeCard({required this.code});

  final String code;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SectionCard(
      title: 'Your recovery code',
      subtitle: 'Shown once. The server stores only a salted hash.',
      trailing: IconButton(
        tooltip: 'Copy recovery code',
        icon: const Icon(Icons.copy),
        onPressed: () => copyToClipboard(context, code, what: 'Recovery code'),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          SelectableText(
            code,
            key: const Key('recovery-code'),
            textAlign: TextAlign.center,
            style: monospaceStyle(context, base: theme.textTheme.headlineSmall)
                .copyWith(letterSpacing: 2),
          ),
          const SizedBox(height: 8),
          const Explainer(
            'Write it down. If this key is lost or invalidated — for example '
            'after you enroll a new fingerprint — the code lets you bind a '
            'new key to the same account. Using it retires the old key and '
            'issues a new code.',
          ),
        ],
      ),
    );
  }
}
