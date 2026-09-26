import 'package:flutter/material.dart';

import '../../attestation/attestation_report.dart';
import '../../attestation/key_description.dart';
import '../../encoding/bytes.dart';
import '../theme.dart';
import 'check_row.dart';
import 'copy.dart';
import 'key_value_row.dart';
import 'section_card.dart';
import 'status_chip.dart';

/// Renders an [AttestationReport]: trust tier, every check, the key
/// description highlights and the certificate chain (with "copy as PEM").
///
/// A column meant to live inside a scroll view.
class AttestationReportView extends StatelessWidget {
  /// Creates the view.
  const AttestationReportView({super.key, required this.report});

  /// The report.
  final AttestationReport report;

  @override
  Widget build(BuildContext context) {
    final kd = report.keyDescription;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _Header(report: report),
        const SizedBox(height: 12),
        SectionCard(
          title: 'Checks',
          subtitle: 'What a server must verify before trusting the key',
          child: Column(
            children: [
              for (final c in report.checks) CheckRow.fromCheck(c),
            ],
          ),
        ),
        if (kd != null) ...[
          const SizedBox(height: 12),
          _KeyDescriptionCard(kd: kd),
        ],
        if (report.certificates.isNotEmpty) ...[
          const SizedBox(height: 12),
          _ChainCard(report: report),
        ],
      ],
    );
  }
}

class _Header extends StatelessWidget {
  const _Header({required this.report});

  final AttestationReport report;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final kind = statusKindForTier(report.trustTier);
    final colors = context.statusColors;
    final fg = colors.onContainer(kind, theme.colorScheme);
    final failures = report.failures.length;
    final warnings = report.warnings.length;
    final summary = report.passed
        ? 'Verified${warnings > 0 ? ' with $warnings warning${warnings == 1 ? '' : 's'}' : ''}'
        : report.trustTier == TrustTier.none
            ? 'No attestation to verify'
            : '$failures check${failures == 1 ? '' : 's'} failed';
    return Semantics(
      container: true,
      label: 'Trust tier ${report.trustTier.label}. $summary',
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: colors.container(kind, theme.colorScheme),
          borderRadius: BorderRadius.circular(16),
        ),
        child: Row(
          children: [
            Icon(
              report.passed ? Icons.verified_user : Icons.gpp_maybe,
              color: fg,
              size: 36,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(report.trustTier.label,
                      style: theme.textTheme.titleLarge?.copyWith(color: fg)),
                  Text(summary,
                      style: theme.textTheme.bodyMedium?.copyWith(color: fg)),
                  Text(
                    'Checked ${report.verifiedAt.toUtc().toIso8601String()}',
                    style: theme.textTheme.bodySmall?.copyWith(color: fg),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _KeyDescriptionCard extends StatelessWidget {
  const _KeyDescriptionCard({required this.kd});

  final KeyDescription kd;

  @override
  Widget build(BuildContext context) {
    final hw = kd.hardwareEnforced;
    final sw = kd.softwareEnforced;
    final rot = kd.rootOfTrust;
    final app = kd.attestationApplicationId;
    String names(List<int>? values, Map<int, String> table) => values == null
        ? '—'
        : values.map((v) => KeyMintNames.name(table, v)).join(', ');
    return SectionCard(
      title: 'Key description',
      subtitle: 'Hardware-enforced unless noted',
      child: Column(
        children: [
          KeyValueRow(
            label: 'Attestation',
            value: '${kd.implementationName} v${kd.attestationVersion} · '
                '${kd.attestationSecurityLevel.label} (key: '
                '${kd.keyMintSecurityLevel.label})',
            copyable: false,
          ),
          KeyValueRow(
            label: 'Challenge',
            value: toHex(kd.attestationChallenge),
            monospace: true,
          ),
          KeyValueRow(
            label: 'Algorithm',
            value: [
              if (hw.algorithm != null)
                KeyMintNames.name(KeyMintNames.algorithms, hw.algorithm!),
              if (hw.ecCurve != null)
                KeyMintNames.name(KeyMintNames.ecCurves, hw.ecCurve!)
              else if (hw.keySize != null)
                '${hw.keySize} bits',
            ].join(' '),
            copyable: false,
          ),
          KeyValueRow(
            label: 'Purposes',
            value: names(hw.purposes, KeyMintNames.purposes),
            copyable: false,
          ),
          KeyValueRow(
            label: 'Digests',
            value: names(hw.digests, KeyMintNames.digests),
            copyable: false,
          ),
          KeyValueRow(
            label: 'User auth',
            value: hw.noAuthRequired
                ? 'noAuthRequired (no user authentication)'
                : KeyMintNames.userAuthType(hw.userAuthType),
            copyable: false,
          ),
          KeyValueRow(
            label: 'Origin',
            value: hw.origin?.label ?? '${hw.originValue ?? '—'}',
            copyable: false,
          ),
          if (rot != null)
            KeyValueRow(
              label: 'Root of trust',
              value: '${rot.deviceLocked ? 'Locked' : 'Unlocked'} · '
                  '${rot.verifiedBootState.label}',
              copyable: false,
            ),
          KeyValueRow(
            label: 'OS',
            value: 'Android ${KeyMintNames.osVersion(hw.osVersion)} · patch '
                '${KeyMintNames.patchLevel(hw.osPatchLevel)}',
            copyable: false,
          ),
          if (app != null)
            KeyValueRow(
              label: 'App (software)',
              value: app.packageNames.join(', '),
            ),
          if (sw.creationTime != null)
            KeyValueRow(
              label: 'Created (software)',
              value: sw.creationTime!.toIso8601String(),
              copyable: false,
            ),
        ],
      ),
    );
  }
}

class _ChainCard extends StatelessWidget {
  const _ChainCard({required this.report});

  final AttestationReport report;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SectionCard(
      title: 'Certificate chain',
      subtitle: 'Leaf first · ${report.certificates.length} certificates',
      trailing: report.chain.isEmpty
          ? null
          : TextButton.icon(
              icon: const Icon(Icons.copy, size: 18),
              label: const Text('Copy chain as PEM'),
              onPressed: () => copyToClipboard(context, report.chainPem,
                  what: 'Certificate chain'),
            ),
      child: Column(
        children: [
          for (final c in report.certificates)
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              title: Text('#${c.index} ${c.subject}',
                  maxLines: 2, overflow: TextOverflow.ellipsis),
              subtitle: Text('${c.publicKey} · ${c.signatureAlgorithm}',
                  style: theme.textTheme.bodySmall),
              trailing: c.index == report.selectedCertificateIndex
                  ? const StatusChip(
                      label: 'attestation', kind: StatusKind.info)
                  : null,
              children: [
                KeyValueRow(label: 'Subject', value: c.subject),
                KeyValueRow(label: 'Issuer', value: c.issuer),
                KeyValueRow(
                  label: 'Valid',
                  value: '${c.notBefore.toIso8601String()} → '
                      '${c.notAfter.toIso8601String()}',
                  copyable: false,
                ),
                KeyValueRow(
                  label: 'SHA-256',
                  value: c.sha256Fingerprint,
                  monospace: true,
                ),
                if (c.hasKeyAttestationExtension)
                  const KeyValueRow(
                    label: 'Extension',
                    value: 'Key attestation (1.3.6.1.4.1.11129.2.1.17)',
                    copyable: false,
                  ),
              ],
            ),
        ],
      ),
    );
  }
}
