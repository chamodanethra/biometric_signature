import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/bank_client.dart';
import '../money.dart';
import '../server/models.dart';
import '../widgets/bank_widgets.dart';
import 'reverify_screen.dart';

/// Both keys: local health (`getKeyInfo(checkValidity: true)`), what the
/// bank registered, attestation reports, rotation and unbinding.
class SecurityScreen extends StatefulWidget {
  /// Creates the screen.
  const SecurityScreen({super.key});

  @override
  State<SecurityScreen> createState() => _SecurityScreenState();
}

class _SecurityScreenState extends State<SecurityScreen> {
  bool _busy = false;
  String? _message;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback(
        (_) => AppScope.of(context).session.recheckKeys());
  }

  Future<bool> _confirm(String title, String message, String action) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: Text(message),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: Text(action)),
        ],
      ),
    );
    return ok ?? false;
  }

  Future<void> _deleteApprovalKey() async {
    final services = AppScope.of(context);
    if (!await _confirm(
        'Delete the approval key?',
        'deleteKeys(keyAlias: "${KeyAliases.approval}") removes it from this '
            'device only. Approvals lock until you re-verify — the same '
            'recovery as after a biometric enrollment change.',
        'Delete')) {
      return;
    }
    await services.keys.deleteKey(KeyAliases.approval);
    await services.session.recheckKeys();
  }

  Future<void> _unbind() async {
    final services = AppScope.of(context);
    if (!await _confirm(
        'Unbind this device?',
        'The bank revokes this device and both keys; then the app deletes '
            'them with deleteKeys. You will need to bind the device again.',
        'Unbind')) {
      return;
    }
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await services.unbindDevice();
    } on BankError catch (e) {
      if (mounted) setState(() => _message = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final session = services.session;
    return ListenableBuilder(
      listenable: session,
      builder: (context, _) {
        final enrollment = session.enrollment;
        final device = session.snapshot?.device;
        final approval = device?.activeApprovalKey;
        return BankScaffold(
          title: 'Keys & security',
          body: ListView(
            padding: pagePadding(context),
            children: [
              if (device == null)
                const CapabilityBanner(
                  title: 'Bank records not loaded',
                  message: 'Pull to refresh on the home screen to see what '
                      'the bank registered.',
                ),
              if (device == null) gap,
              _KeyCard(
                title: '${KeyAliases.deviceBinding} — device possession',
                explanation: 'Created with requireAuthentication: false, so '
                    'it signs every request without a prompt. It proves the '
                    'request comes from this device, not that you are '
                    'present, so on its own it cannot satisfy strong '
                    'customer authentication. It is never invalidated by '
                    'enrollment changes, which is what lets it re-verify '
                    'you.',
                health: session.deviceKeyHealth,
                localFingerprint: enrollment?.deviceKeyFingerprint,
                registered: device?.deviceKey,
              ),
              gap,
              _KeyCard(
                title: '${KeyAliases.approval} — your approval',
                explanation: 'enforceBiometric, '
                    'setInvalidatedByBiometricEnrollment: true, '
                    'useDeviceCredentials: '
                    '${enrollment?.allowDeviceCredential ?? false}. Adding or '
                    'removing a fingerprint or face invalidates it '
                    '(keyInvalidated).',
                health: session.approvalKeyHealth,
                localFingerprint: enrollment?.approvalKeyFingerprint,
                registered: approval,
                footer: device == null
                    ? null
                    : () {
                        final policy = session.snapshot!.policy;
                        final decision =
                            policy.evaluate(policy.tierBLimitCents + 1, device);
                        return KeyValueRow(
                          label: 'Tier C',
                          value: decision.allowed
                              ? decision.assurance
                              : decision.reason!,
                          copyable: false,
                          trailing: StatusChip(
                            label: decision.allowed ? 'Allowed' : 'Capped',
                            kind: decision.allowed
                                ? StatusKind.success
                                : StatusKind.warning,
                          ),
                        );
                      }(),
                actions: [
                  OutlinedButton.icon(
                    onPressed: () => Navigator.of(context).push(
                      MaterialPageRoute(
                        builder: (_) => const ReverifyScreen(
                          reason: 'rotation',
                          explanation: 'You asked to rotate your approval '
                              'key.',
                        ),
                      ),
                    ),
                    icon: const Icon(Icons.autorenew),
                    label: const Text('Rotate approval key'),
                  ),
                  OutlinedButton.icon(
                    onPressed: _deleteApprovalKey,
                    icon: const Icon(Icons.delete_outline),
                    label: const Text('Delete on this device'),
                  ),
                ],
              ),
              if (device != null &&
                  device.approvalKeys.any((k) => !k.isActive)) ...[
                gap,
                SectionCard(
                  title: 'Revoked approval keys',
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      for (final k
                          in device.approvalKeys.where((k) => !k.isActive))
                        KeyValueRow(
                          label: formatFingerprint(k.fingerprint, maxGroups: 2),
                          value: '${k.revokeReason ?? 'revoked'} · '
                              '${k.revokedAt == null ? '' : formatDateTime(k.revokedAt!)}',
                          copyable: false,
                        ),
                    ],
                  ),
                ),
              ],
              gap,
              SectionCard(
                title: 'This device',
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    KeyValueRow(
                        label: 'Device id', value: enrollment?.deviceId ?? '—'),
                    KeyValueRow(
                        label: 'Platform',
                        value: services.platform.label,
                        copyable: false),
                    KeyValueRow(
                        label: 'Bound',
                        value: enrollment == null
                            ? '—'
                            : formatDateTime(enrollment.enrolledAt),
                        copyable: false),
                    const SizedBox(height: 8),
                    if (_message != null) ...[
                      Text(_message!,
                          style: TextStyle(color: context.statusColors.danger)),
                      const SizedBox(height: 8),
                    ],
                    Align(
                      alignment: Alignment.centerLeft,
                      child: FilledButton.tonalIcon(
                        onPressed: _busy ? null : _unbind,
                        icon: const Icon(Icons.link_off),
                        label: const Text('Unbind this device'),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _KeyCard extends StatelessWidget {
  const _KeyCard({
    required this.title,
    required this.explanation,
    required this.health,
    required this.localFingerprint,
    required this.registered,
    this.footer,
    this.actions = const [],
  });

  final String title;
  final String explanation;
  final KeyHealth? health;
  final String? localFingerprint;
  final RegisteredKey? registered;
  final Widget? footer;
  final List<Widget> actions;

  @override
  Widget build(BuildContext context) {
    final key = registered;
    final onDevice = health?.info.publicKey == null
        ? null
        : _fingerprint(health!.info.publicKey!);
    return SectionCard(
      title: title,
      trailing: KeyHealthChip(health),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(explanation),
          const SizedBox(height: 8),
          KeyValueRow(
            label: 'On this device',
            value: onDevice == null
                ? (health?.summary ?? 'Not checked')
                : formatFingerprint(onDevice, maxGroups: 4),
            copyable: false,
            trailing: onDevice == null || localFingerprint == null
                ? null
                : StatusChip(
                    label: onDevice == localFingerprint
                        ? 'Registered'
                        : 'Not registered',
                    kind: onDevice == localFingerprint
                        ? StatusKind.success
                        : StatusKind.danger,
                  ),
          ),
          if (key != null) ...[
            KeyValueRow(
                label: 'Bank record',
                value: '${key.description} · registered '
                    '${formatDateTime(key.registeredAt)}',
                copyable: false),
            KeyValueRow(
              label: 'Attestation',
              value: key.trustTier == TrustTier.none
                  ? key.attestation.checks.first.detail
                  : key.trustTier.label,
              copyable: false,
              trailing: TrustChip(key.trustTier),
            ),
            KeyValueRow(
                label: 'Auth policy',
                value: key.authPolicySummary,
                copyable: false),
            if (key.trustTier != TrustTier.none)
              Align(
                alignment: Alignment.centerLeft,
                child: TextButton.icon(
                  onPressed: () => Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => Scaffold(
                        appBar: AppBar(title: Text('${key.alias} attestation')),
                        body: ListView(
                          padding: pagePadding(context),
                          children: [
                            AttestationReportView(report: key.attestation),
                          ],
                        ),
                      ),
                    ),
                  ),
                  icon: const Icon(Icons.verified_outlined),
                  label: const Text('View attestation report'),
                ),
              ),
          ],
          if (footer != null) footer!,
          if (actions.isNotEmpty) ...[
            const SizedBox(height: 8),
            Wrap(spacing: 8, runSpacing: 8, children: actions),
          ],
        ],
      ),
    );
  }

  static String? _fingerprint(String publicKey) {
    try {
      return ParsedPublicKey.parse(publicKey).fingerprint;
    } on FormatException {
      return null;
    }
  }
}
