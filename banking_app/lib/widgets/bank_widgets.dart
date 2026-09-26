/// Small widgets shared by the screens.
library;

import 'dart:math' as math;

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../screens/server_console.dart';
import '../server/bank_server.dart';
import '../server/models.dart';

/// Horizontal padding that centres content at most 760 px wide.
EdgeInsets pagePadding(BuildContext context) {
  final width = MediaQuery.sizeOf(context).width;
  final side = math.max(16.0, (width - 760) / 2);
  return EdgeInsets.fromLTRB(side, 16, side, 96);
}

/// A scaffold with the bank server console in the app bar.
class BankScaffold extends StatelessWidget {
  /// Creates the scaffold.
  const BankScaffold({
    super.key,
    required this.title,
    required this.body,
    this.actions = const [],
    this.floatingActionButton,
  });

  /// Title.
  final String title;

  /// Body.
  final Widget body;

  /// App bar actions (before the console button).
  final List<Widget> actions;

  /// Floating action button.
  final Widget? floatingActionButton;

  @override
  Widget build(BuildContext context) {
    return DevConsoleScaffold(
      title: Text(title),
      body: body,
      actions: actions,
      floatingActionButton: floatingActionButton,
      consoleTabs: buildServerConsoleTabs(AppScope.of(context)),
      consoleTooltip: 'Bank server console',
    );
  }
}

/// `Tier A` / `Tier B` / `Tier C`.
class TierChip extends StatelessWidget {
  /// Creates the chip.
  const TierChip(this.tier, {super.key});

  /// The tier.
  final RiskTier tier;

  @override
  Widget build(BuildContext context) => StatusChip(
        label: 'Tier ${tier.label}',
        kind: switch (tier) {
          RiskTier.a => StatusKind.neutral,
          RiskTier.b => StatusKind.info,
          RiskTier.c => StatusKind.success,
        },
        icon: switch (tier) {
          RiskTier.a => Icons.phonelink_lock,
          RiskTier.b => Icons.fingerprint,
          RiskTier.c => Icons.verified_user,
        },
      );
}

/// A chip for an attestation trust tier.
class TrustChip extends StatelessWidget {
  /// Creates the chip.
  const TrustChip(this.tier, {super.key});

  /// The trust tier.
  final TrustTier tier;

  @override
  Widget build(BuildContext context) =>
      StatusChip(label: tier.label, kind: statusKindForTier(tier));
}

/// A chip for a key probe.
class KeyHealthChip extends StatelessWidget {
  /// Creates the chip.
  const KeyHealthChip(this.health, {super.key});

  /// The probe result (`null` = not probed yet).
  final KeyHealth? health;

  @override
  Widget build(BuildContext context) {
    final h = health;
    if (h == null) return const StatusChip(label: 'Not checked');
    return switch (h.status) {
      KeyHealthStatus.healthy =>
        const StatusChip(label: 'Present, valid', kind: StatusKind.success),
      KeyHealthStatus.invalidated =>
        const StatusChip(label: 'Invalidated', kind: StatusKind.danger),
      KeyHealthStatus.missing =>
        const StatusChip(label: 'Missing', kind: StatusKind.danger),
    };
  }
}

/// A list of server checks.
class ChecksView extends StatelessWidget {
  /// Creates the view.
  const ChecksView(this.checks, {super.key, this.emptyText = 'No checks.'});

  /// The checks.
  final List<ServerCheck> checks;

  /// Shown when [checks] is empty.
  final String emptyText;

  @override
  Widget build(BuildContext context) {
    if (checks.isEmpty) return Text(emptyText);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        for (final c in checks)
          CheckRow(
            kind: statusKindForCheck(c.status),
            title: c.title,
            detail: c.detail,
          ),
      ],
    );
  }
}

/// Shows the newest simulated SMS for [subject], with a button that fills
/// the code in.
class SimulatedSmsCard extends StatelessWidget {
  /// Creates the card.
  const SimulatedSmsCard({
    super.key,
    required this.outbox,
    required this.subject,
    required this.onUseCode,
  });

  /// The bank's outbox.
  final SmsOutbox outbox;

  /// Enrollment or re-verification id.
  final String subject;

  /// Called with the code.
  final ValueChanged<String> onUseCode;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: outbox.asListenable,
      builder: (context, _) {
        final sms = outbox.latestFor(subject);
        if (sms == null) return const SizedBox.shrink();
        return CapabilityBanner(
          kind: StatusKind.info,
          icon: Icons.sms_outlined,
          title: 'Simulated SMS to ${sms.to}',
          message: '${sms.text}\n\nA real bank sends this over a separate '
              'channel; the demo shows it here.',
          action: FilledButton.tonal(
            key: const ValueKey('use-sms-code'),
            onPressed: () => onUseCode(sms.code),
            child: Text('Use code ${sms.code}'),
          ),
        );
      },
    );
  }
}

/// A linear progress bar with the current step.
class BusyStep extends StatelessWidget {
  /// Creates the indicator.
  const BusyStep(this.step, {super.key});

  /// What is happening.
  final String step;

  @override
  Widget build(BuildContext context) => Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const LinearProgressIndicator(),
          const SizedBox(height: 8),
          Text(step, style: Theme.of(context).textTheme.bodySmall),
        ],
      );
}

/// Vertical spacing between page sections.
const Widget gap = SizedBox(height: 12);
