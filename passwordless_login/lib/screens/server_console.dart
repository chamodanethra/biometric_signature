import 'dart:convert';

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app_scope.dart';
import '../server/models.dart';
import '../server/policy.dart';
import 'attestation_report_screen.dart';

/// The server console: records, audit log, wire log, policy and faults.
List<DevConsoleTab> serverConsoleTabs(AppServices services) => [
      DevConsoleTab(
        label: 'Records',
        icon: Icons.storage_outlined,
        builder: (_) => _RecordsTab(services: services),
      ),
      DevConsoleTab(
        label: 'Audit',
        icon: Icons.fact_check_outlined,
        builder: (_) => AuditLogView(log: services.server.audit),
      ),
      DevConsoleTab(
        label: 'Wire',
        icon: Icons.swap_horiz,
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

String _time(DateTime? t) {
  if (t == null) return '—';
  final l = t.toLocal();
  String two(int v) => v.toString().padLeft(2, '0');
  return '${l.year}-${two(l.month)}-${two(l.day)} '
      '${two(l.hour)}:${two(l.minute)}:${two(l.second)}';
}

class _RecordsTab extends StatelessWidget {
  const _RecordsTab({required this.services});

  final AppServices services;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable:
          Listenable.merge([services.server.asListenable, services.accounts]),
      builder: (context, _) {
        final server = services.server;
        final users = server.users;
        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            const CapabilityBanner(
              title: 'Mock server — demo code',
              message: 'Runs inside this app. Users and device keys persist '
                  'in SharedPreferences (server.*); challenges and sessions '
                  'live in memory. No TLS, rate limits or revocation checks.',
            ),
            const SizedBox(height: 12),
            Wrap(spacing: 8, runSpacing: 8, children: [
              StatusChip(label: '${users.length} users', showIcon: false),
              StatusChip(
                  label: '${server.deviceKeys.length} device keys',
                  showIcon: false),
              StatusChip(
                  label: '${server.sessions.length} sessions', showIcon: false),
              StatusChip(
                  label: '${server.challenges.outstanding} open challenges',
                  showIcon: false),
            ]),
            const SizedBox(height: 12),
            if (users.isEmpty) const Text('No users registered.'),
            for (final user in users)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: SectionCard(
                  title: user.username,
                  subtitle: '${user.userId} · created ${_time(user.createdAt)}'
                      ' · recovery code issued '
                      '${_time(user.recoveryCodeIssuedAt)}',
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      for (final d in server.deviceKeys)
                        if (d.userId == user.userId)
                          _DeviceTile(
                            device: d,
                            orphaned: d.isActive &&
                                services.accounts
                                        .byDeviceKeyId(d.deviceKeyId) ==
                                    null,
                          ),
                    ],
                  ),
                ),
              ),
          ],
        );
      },
    );
  }
}

class _DeviceTile extends StatelessWidget {
  const _DeviceTile({required this.device, required this.orphaned});

  final DeviceKeyRecord device;
  final bool orphaned;

  @override
  Widget build(BuildContext context) {
    final d = device;
    return ExpansionTile(
      tilePadding: EdgeInsets.zero,
      title: Text('${d.alias} · ${d.deviceKeyId}',
          style: monospaceStyle(context,
              base: Theme.of(context).textTheme.bodyMedium)),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: 4),
        child: Wrap(spacing: 6, runSpacing: 6, children: [
          StatusChip(
            label: d.status.name,
            kind: d.isActive ? StatusKind.success : StatusKind.neutral,
          ),
          StatusChip(
              label: d.trustTier.label, kind: statusKindForTier(d.trustTier)),
          if (orphaned)
            const StatusChip(
              label: 'orphaned: no account on this device',
              kind: StatusKind.warning,
            ),
        ]),
      ),
      childrenPadding: const EdgeInsets.only(bottom: 8),
      children: [
        KeyValueRow(
            label: 'Declared platform', value: d.platform, copyable: false),
        KeyValueRow(
            label: 'Algorithm', value: d.algorithm.label, copyable: false),
        KeyValueRow(
          label: 'Public key SHA-256',
          value: formatFingerprint(d.fingerprint, maxGroups: 8),
          monospace: true,
          copyable: false,
        ),
        KeyValueRow(
            label: 'Public key (SPKI)', value: d.publicKey, monospace: true),
        KeyValueRow(
          label: 'Created',
          value: _time(d.createdAt),
          copyable: false,
        ),
        KeyValueRow(
          label: 'Declared options',
          value: '${d.allowDeviceCredentials ? 'PIN allowed' : 'biometric '
              'only'} · ${d.invalidateOnEnrollment ? 'invalidated by '
              'enrollment changes' : 'survives enrollment changes'}',
          copyable: false,
        ),
        KeyValueRow(
          label: 'Sign-ins',
          value: '${d.loginCount} · last ${_time(d.lastLoginAt)} · '
              'authenticationType ${d.lastAuthenticationType ?? '—'} '
              '(client-reported)',
          copyable: false,
        ),
        if (d.supersededBy != null)
          KeyValueRow(
              label: 'Superseded by', value: d.supersededBy!, monospace: true),
        Align(
          alignment: Alignment.centerLeft,
          child: TextButton.icon(
            onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(
              builder: (_) => AttestationReportScreen(report: d.report),
            )),
            icon: const Icon(Icons.verified_user_outlined),
            label: const Text('Attestation report'),
          ),
        ),
      ],
    );
  }
}

class _PolicyTab extends StatelessWidget {
  const _PolicyTab({required this.services});

  final AppServices services;

  @override
  Widget build(BuildContext context) {
    final server = services.server;
    return ListenableBuilder(
      listenable: server.asListenable,
      builder: (context, _) {
        final p = server.policy;
        void update(ServerPolicy next) => server.updatePolicy(next);
        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            SwitchListTile(
              key: const Key('policy-require-attestation'),
              contentPadding: EdgeInsets.zero,
              value: p.requireAttestation,
              onChanged: (v) => update(p.copyWith(requireAttestation: v)),
              title: const Text('Require attestation'),
              subtitle: const Text(
                'On: only keys with a verified Android attestation register; '
                'iOS, macOS and Windows are rejected. Off: they register as '
                '"Not attested", and a chain that fails verification is '
                'accepted as "Untrusted".',
              ),
            ),
            const Divider(),
            Text('Accepted security levels',
                style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 8),
            Wrap(spacing: 8, children: [
              for (final level in const [
                SecurityLevel.trustedEnvironment,
                SecurityLevel.strongBox,
              ])
                FilterChip(
                  label: Text(level.label),
                  selected: p.allowedSecurityLevels.contains(level),
                  onSelected: (on) {
                    final next = {...p.allowedSecurityLevels};
                    if (on) {
                      next.add(level);
                    } else {
                      next.remove(level);
                    }
                    if (next.isNotEmpty) {
                      update(p.copyWith(allowedSecurityLevels: next));
                    }
                  },
                ),
            ]),
            const SizedBox(height: 4),
            const Text('Software keys are always rejected. Deselect TEE to '
                'accept StrongBox keys only.'),
            const Divider(),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              value: p.expectedPackage != null,
              onChanged: (v) => update(v
                  ? p.copyWith(expectedPackage: attestedPackageName)
                  : p.copyWith(clearExpectedPackage: true)),
              title: const Text('Check the attested app package'),
              subtitle: Text(p.expectedPackage ?? 'Report only'),
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              value: p.requireLockedBootloader,
              onChanged: (v) => update(p.copyWith(requireLockedBootloader: v)),
              title: const Text('Require a locked bootloader'),
              subtitle: const Text('Off: an unlocked bootloader or '
                  'unverified boot is a warning, not a failure.'),
            ),
            const Divider(),
            Text('Login nonce lifetime',
                style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 8),
            SegmentedButton<int>(
              segments: const [
                ButtonSegment(value: 30, label: Text('30 s')),
                ButtonSegment(value: 120, label: Text('2 min')),
                ButtonSegment(value: 300, label: Text('5 min')),
              ],
              selected: {p.loginNonceTtl.inSeconds},
              emptySelectionAllowed: true,
              onSelectionChanged: (s) {
                if (s.isEmpty) return;
                update(p.copyWith(loginNonceTtl: Duration(seconds: s.first)));
              },
            ),
            const SizedBox(height: 12),
            Text('Registration challenge lifetime',
                style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 8),
            SegmentedButton<int>(
              segments: const [
                ButtonSegment(value: 120, label: Text('2 min')),
                ButtonSegment(value: 300, label: Text('5 min')),
                ButtonSegment(value: 600, label: Text('10 min')),
              ],
              selected: {p.registrationChallengeTtl.inSeconds},
              emptySelectionAllowed: true,
              onSelectionChanged: (s) {
                if (s.isEmpty) return;
                update(p.copyWith(
                    registrationChallengeTtl: Duration(seconds: s.first)));
              },
            ),
            const SizedBox(height: 16),
            const CapabilityBanner(
              kind: StatusKind.warning,
              title: 'Not configurable here — real-server duties',
              message: 'Revocation: check every chain certificate against '
                  'https://android.googleapis.com/attestation/status. '
                  'Signing certificate: pin your release signing-certificate '
                  'SHA-256 digest (AttestationPolicy.'
                  'expectedSigningCertificateDigests); this demo only reports '
                  'it, because debug builds are signed with a throwaway key.',
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
  String? _replayResult;

  AppServices get _s => widget.services;

  static Object? _flipLastBit(Object? value) {
    if (value is! String || value.isEmpty) return value;
    final bytes = base64.decode(value);
    bytes[bytes.length - 1] ^= 0x01;
    return base64.encode(bytes);
  }

  Future<void> _replay() async {
    final response = await _s.transport.replayLast(ApiRoutes.loginFinish);
    if (!mounted) return;
    setState(() => _replayResult = response['ok'] == true
        ? 'Replay ACCEPTED — this should never happen.'
        : 'Replay rejected: ${response['reason']}');
  }

  Future<void> _reset() async {
    final navigator = Navigator.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Reset the demo?'),
        content: const Text('Deletes every key (deleteAllKeys), all server '
            'records, the audit log and all local accounts.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Reset'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    await _s.resetDemo();
    navigator.pop();
  }

  @override
  Widget build(BuildContext context) {
    final transport = _s.transport;
    final server = _s.server;
    return ListenableBuilder(
      listenable:
          Listenable.merge([transport.asListenable, server.asListenable]),
      builder: (context, _) {
        final faults = transport.pendingFaults;
        final jumps = server.pendingClockJumps;
        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            const Text('Arm a fault, then run the flow. Each one shows a '
                'server check doing its job.'),
            const SizedBox(height: 12),
            _FaultButton(
              icon: Icons.cloud_off,
              title: 'Fail the next registration upload',
              detail: 'The key is created, but /register/finish never '
                  'arrives. Retry reads the chain back with getKeyInfo; the '
                  'server kept the challenge.',
              onPressed: () => transport.failNext(ApiRoutes.registerFinish),
            ),
            _FaultButton(
              icon: Icons.cloud_off,
              title: 'Fail the next recovery upload',
              detail: 'Same, for /recovery/finish.',
              onPressed: () => transport.failNext(ApiRoutes.recoveryFinish),
            ),
            _FaultButton(
              icon: Icons.edit_note,
              title: 'Tamper with the next login signature',
              detail: 'Flips one bit in transit → "ECDSA signature mismatch".',
              onPressed: () => transport.tamper(
                  ApiRoutes.loginFinish, 'signature', _flipLastBit),
            ),
            _FaultButton(
              icon: Icons.person_off_outlined,
              title: 'Present the next login as another user',
              detail: 'Rewrites userId in transit → the nonce is bound to a '
                  'different subject.',
              onPressed: () => transport.tamper(ApiRoutes.loginFinish, 'userId',
                  Tamper.replaceWith('u_mallory')),
            ),
            _FaultButton(
              icon: Icons.timer_off_outlined,
              title: 'Expire the next login nonce',
              detail: 'Moves the server clock forward 5 minutes just before '
                  '/login/finish → "challenge expired".',
              onPressed: () => server.jumpClockBeforeNext(
                  ApiRoutes.loginFinish, const Duration(minutes: 5)),
            ),
            _FaultButton(
              icon: Icons.replay,
              title: 'Replay the last login',
              detail: transport.canReplay(ApiRoutes.loginFinish)
                  ? 'Re-sends the captured /login/finish byte for byte → the '
                      'nonce was already consumed.'
                  : 'Sign in once first.',
              actionLabel: 'Replay',
              onPressed:
                  transport.canReplay(ApiRoutes.loginFinish) ? _replay : null,
            ),
            if (_replayResult != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: CapabilityBanner(
                  kind: _replayResult!.startsWith('Replay rejected')
                      ? StatusKind.success
                      : StatusKind.danger,
                  title: 'Replay result',
                  message: _replayResult!,
                ),
              ),
            const Divider(),
            Text('Armed', style: Theme.of(context).textTheme.titleSmall),
            if (faults.isEmpty && jumps.isEmpty)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 8),
                child: Text('Nothing armed.'),
              ),
            for (final f in faults)
              ListTile(
                contentPadding: EdgeInsets.zero,
                dense: true,
                title: Text(f.label),
                trailing: IconButton(
                  tooltip: 'Disarm',
                  icon: const Icon(Icons.close),
                  onPressed: () => transport.removeFault(f),
                ),
              ),
            for (final j in jumps.entries)
              ListTile(
                contentPadding: EdgeInsets.zero,
                dense: true,
                title: Text('clock +${j.value.inMinutes} min before ${j.key}'),
                trailing: IconButton(
                  tooltip: 'Disarm',
                  icon: const Icon(Icons.close),
                  onPressed: server.clearClockJumps,
                ),
              ),
            KeyValueRow(
              label: 'Server clock skew',
              value: '${_s.serverClock.skew.inMinutes} min',
              copyable: false,
              trailing: TextButton(
                onPressed: _s.serverClock.skew == Duration.zero
                    ? null
                    : () => setState(() => _s.serverClock.skew = Duration.zero),
                child: const Text('Reset'),
              ),
            ),
            const Divider(),
            OutlinedButton.icon(
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

class _FaultButton extends StatelessWidget {
  const _FaultButton({
    required this.icon,
    required this.title,
    required this.detail,
    required this.onPressed,
    this.actionLabel = 'Arm',
  });

  final IconData icon;
  final String title;
  final String detail;
  final VoidCallback? onPressed;
  final String actionLabel;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Icon(icon),
      title: Text(title),
      subtitle: Text(detail),
      trailing: FilledButton.tonal(
        onPressed: onPressed,
        child: Text(actionLabel),
      ),
    );
  }
}
