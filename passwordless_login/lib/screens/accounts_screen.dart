import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app_scope.dart';
import '../client/accounts.dart';
import '../client/auth_client.dart';
import '../client/outcome.dart';
import '../client/preflight.dart';
import '../widgets/app_scaffold.dart';
import '../widgets/outcome_view.dart';
import 'account_detail_screen.dart';
import 'attestation_report_screen.dart';
import 'login_screen.dart';
import 'preflight_screen.dart';
import 'recovery_screen.dart';
import 'register_screen.dart';

enum _Menu { deviceCheck, wipe, reset }

/// Home: the accounts bound to this device, with their key health.
class AccountsScreen extends StatefulWidget {
  /// Creates the screen.
  const AccountsScreen({super.key});

  @override
  State<AccountsScreen> createState() => _AccountsScreenState();
}

class _AccountsScreenState extends State<AccountsScreen> {
  PreflightResult? _preflight;
  bool _checking = false;
  bool _uploading = false;
  AuthOutcome<Registration>? _uploadOutcome;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _refresh());
  }

  Future<void> _refresh() async {
    final services = AppScope.of(context);
    setState(() => _checking = true);
    final preflight = await services.client.preflight();
    await services.client.reconcile();
    if (!mounted) return;
    setState(() {
      _preflight = preflight;
      _checking = false;
    });
  }

  Future<void> _push(Widget screen) async {
    await Navigator.of(context)
        .push(MaterialPageRoute<void>(builder: (_) => screen));
    if (mounted) await _refresh();
  }

  Future<void> _retryUpload() async {
    final services = AppScope.of(context);
    setState(() {
      _uploading = true;
      _uploadOutcome = null;
    });
    final outcome = await services.client.retryUpload();
    if (!mounted) return;
    setState(() {
      _uploading = false;
      _uploadOutcome = outcome;
    });
    if (outcome case Success(:final value)) {
      setState(() => _uploadOutcome = null);
      await _push(
          AttestationReportScreen(report: value.report, registration: value));
    }
  }

  Future<void> _menu(_Menu choice) async {
    final services = AppScope.of(context);
    switch (choice) {
      case _Menu.deviceCheck:
        await _push(const PreflightScreen());
      case _Menu.wipe:
        final ok = await _confirm(
          'Wipe this device?',
          'Calls deleteAllKeys() and forgets every account on this device. '
              'The server keeps its records; they show up as orphaned in the '
              'server console. Use a recovery code to bind this device again.',
          'Wipe',
        );
        if (!ok) return;
        await services.client.wipeDevice();
        _snack('All keys deleted');
      case _Menu.reset:
        final ok = await _confirm(
          'Reset the demo?',
          'Deletes every key (deleteAllKeys), all server records, the audit '
              'log and all local accounts.',
          'Reset',
        );
        if (!ok) return;
        await services.resetDemo();
        _snack('Demo reset');
    }
    if (mounted) await _refresh();
  }

  Future<bool> _confirm(String title, String message, String action) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: Text(message),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(action),
          ),
        ],
      ),
    );
    return result ?? false;
  }

  void _snack(String text) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
  }

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    return AppScaffold(
      title: 'Passwordless Login',
      actions: [
        IconButton(
          tooltip: 'Re-check keys',
          onPressed: _checking ? null : _refresh,
          icon: const Icon(Icons.refresh),
        ),
        PopupMenuButton<_Menu>(
          onSelected: _menu,
          itemBuilder: (_) => const [
            PopupMenuItem(
                value: _Menu.deviceCheck, child: Text('Device check')),
            PopupMenuItem(value: _Menu.wipe, child: Text('Wipe device keys')),
            PopupMenuItem(value: _Menu.reset, child: Text('Reset demo')),
          ],
        ),
      ],
      body: ListenableBuilder(
        listenable: services.accounts,
        builder: (context, _) {
          final accounts = services.accounts.accounts;
          final pending = services.accounts.pending;
          return PageList(children: [
            if (_checking) const LinearProgressIndicator(),
            const SectionCard(
              title: 'Attested device binding',
              subtitle: 'Replay-resistant challenge-response sign-in',
              child: Explainer(
                'Each account gets its own hardware key on this device. At '
                'registration the server checks Android key attestation and '
                'assigns a trust tier; to sign in, the key signs a one-time '
                'server nonce. The server is a mock running inside this app — '
                'open the console (top right) to inspect records, change the '
                'policy or inject faults.',
              ),
            ),
            ...platformBanners(context,
                onOpenConsole: () => openServerConsole(context)),
            _PreflightCard(
              result: _preflight,
              onOpen: () => _push(const PreflightScreen()),
            ),
            if (pending != null)
              CapabilityBanner(
                kind: StatusKind.warning,
                icon: Icons.cloud_upload_outlined,
                title: 'A key was not uploaded',
                message: 'The key ${pending.alias} for "${pending.username}" '
                    'exists on this device, but its ${pending.kind.name} '
                    'never reached the server. The server keeps the challenge '
                    'until it expires, so the same key and attestation can be '
                    're-sent.',
                action: Wrap(spacing: 8, runSpacing: 8, children: [
                  FilledButton(
                    key: const Key('retry-upload'),
                    onPressed: _uploading ? null : _retryUpload,
                    child: const Text('Retry upload'),
                  ),
                  TextButton(
                    onPressed: _uploading
                        ? null
                        : () async {
                            await services.client.discardPending();
                            if (mounted) setState(() => _uploadOutcome = null);
                          },
                    child: const Text('Discard key'),
                  ),
                ]),
              ),
            if (_uploadOutcome != null)
              OutcomeView(outcome: _uploadOutcome!, onRetry: _retryUpload),
            Text('On this device (${accounts.length})',
                style: Theme.of(context).textTheme.titleMedium),
            if (accounts.isEmpty)
              const Explainer('No accounts yet. Create one, or sign in to an '
                  'existing account whose key is still on this device.'),
            for (final account in accounts)
              _AccountCard(
                key: ValueKey('account-${account.username}'),
                account: account,
                status: services.accounts.statusOf(account.alias),
                onSignIn: () => _push(LoginScreen(account: account)),
                onRebind: () => _push(RecoveryScreen(account: account)),
                onDetails: () =>
                    _push(AccountDetailScreen(alias: account.alias)),
              ),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                FilledButton.icon(
                  key: const Key('create-account'),
                  onPressed: () => _push(const RegisterScreen()),
                  icon: const Icon(Icons.person_add_alt_1),
                  label: const Text('Create account'),
                ),
                OutlinedButton.icon(
                  key: const Key('restore-account'),
                  onPressed: () => _push(const LoginScreen()),
                  icon: const Icon(Icons.login),
                  label: const Text('Sign in to an existing account'),
                ),
                TextButton.icon(
                  onPressed: () => _push(const RecoveryScreen()),
                  icon: const Icon(Icons.key),
                  label: const Text('Recover with a code'),
                ),
              ],
            ),
          ]);
        },
      ),
    );
  }
}

class _PreflightCard extends StatelessWidget {
  const _PreflightCard({required this.result, required this.onOpen});

  final PreflightResult? result;
  final VoidCallback onOpen;

  @override
  Widget build(BuildContext context) {
    final r = result;
    final caps = AppScope.of(context).capabilities;
    return SectionCard(
      title: 'Device check',
      subtitle: 'biometricAuthAvailable() and isDeviceLockSet()',
      trailing: TextButton(onPressed: onOpen, child: const Text('Details')),
      child: r == null
          ? const Explainer('Checking…')
          : Wrap(spacing: 8, runSpacing: 8, children: [
              StatusChip(
                label: r.deviceLockSet ? 'Screen lock set' : 'No screen lock',
                kind: r.deviceLockSet ? StatusKind.success : StatusKind.danger,
              ),
              StatusChip(
                label: r.availability.hasEnrolledBiometrics == true
                    ? 'Biometrics enrolled'
                    : 'No biometrics enrolled',
                kind: r.availability.hasEnrolledBiometrics == true
                    ? StatusKind.success
                    : StatusKind.danger,
              ),
              StatusChip(
                label: caps.supportsAttestation
                    ? 'Key attestation available'
                    : 'No key attestation',
                kind: caps.supportsAttestation
                    ? StatusKind.success
                    : StatusKind.warning,
              ),
            ]),
    );
  }
}

class _AccountCard extends StatelessWidget {
  const _AccountCard({
    super.key,
    required this.account,
    required this.status,
    required this.onSignIn,
    required this.onRebind,
    required this.onDetails,
  });

  final LocalAccount account;
  final AccountStatus status;
  final VoidCallback onSignIn;
  final VoidCallback onRebind;
  final VoidCallback onDetails;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final statusKind = switch (status.state) {
      AccountState.ready => StatusKind.success,
      AccountState.unknown => StatusKind.neutral,
      _ => StatusKind.danger,
    };
    return Card(
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onDetails,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [
                CircleAvatar(
                  child: Text(account.username.substring(0, 1).toUpperCase()),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(account.username,
                          style: theme.textTheme.titleMedium),
                      Text(account.alias,
                          style: monospaceStyle(context).copyWith(
                              color: theme.colorScheme.onSurfaceVariant)),
                    ],
                  ),
                ),
                StatusChip(
                  label: account.trustTier.label,
                  kind: statusKindForTier(account.trustTier),
                  icon: Icons.verified_user_outlined,
                ),
              ]),
              const SizedBox(height: 12),
              Wrap(spacing: 8, runSpacing: 8, children: [
                StatusChip(label: status.label, kind: statusKind),
                if (account.lastLoginAt != null)
                  StatusChip(
                    label: 'Last sign-in ${_ago(account.lastLoginAt!)}',
                    showIcon: false,
                  ),
              ]),
              if (status.needsRebind) ...[
                const SizedBox(height: 8),
                Text(status.message, style: theme.textTheme.bodySmall),
              ],
              const SizedBox(height: 12),
              Row(children: [
                if (status.needsRebind)
                  FilledButton.tonal(
                    key: ValueKey('rebind-${account.username}'),
                    onPressed: onRebind,
                    child: const Text('Re-bind'),
                  )
                else
                  FilledButton.icon(
                    key: ValueKey('sign-in-${account.username}'),
                    onPressed: onSignIn,
                    icon: const Icon(Icons.fingerprint),
                    label: const Text('Sign in'),
                  ),
                const SizedBox(width: 8),
                TextButton(onPressed: onDetails, child: const Text('Details')),
              ]),
            ],
          ),
        ),
      ),
    );
  }

  static String _ago(DateTime t) {
    final d = DateTime.now().toUtc().difference(t);
    if (d.inMinutes < 1) return 'just now';
    if (d.inHours < 1) return '${d.inMinutes} min ago';
    if (d.inDays < 1) return '${d.inHours} h ago';
    return '${d.inDays} d ago';
  }
}
