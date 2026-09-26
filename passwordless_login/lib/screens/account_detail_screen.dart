import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app_scope.dart';
import '../client/accounts.dart';
import '../client/outcome.dart';
import '../client/reconcile.dart';
import '../server/models.dart';
import '../widgets/app_scaffold.dart';
import '../widgets/outcome_view.dart';
import 'attestation_report_screen.dart';
import 'login_screen.dart';
import 'recovery_screen.dart';

/// One account: the key on this device, the server's record, and removal.
class AccountDetailScreen extends StatefulWidget {
  /// Creates the screen for the account with [alias].
  const AccountDetailScreen({super.key, required this.alias});

  /// The account's key alias.
  final String alias;

  @override
  State<AccountDetailScreen> createState() => _AccountDetailScreenState();
}

class _AccountDetailScreenState extends State<AccountDetailScreen> {
  DeviceKeyRecord? _record;
  AuthOutcome<Object?>? _problem;
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Future<void> _load() async {
    final services = AppScope.of(context);
    final account = services.accounts.byAlias(widget.alias);
    if (account == null) return;
    setState(() => _loading = true);
    final status = await reconcileAccount(
        api: services.api, transport: services.transport, account: account);
    services.accounts.setStatus(account.alias, status);
    final record = await services.client.fetchDeviceRecord(account);
    if (!mounted) return;
    setState(() {
      _loading = false;
      _record = record is Success<DeviceKeyRecord> ? record.value : null;
    });
  }

  void _open(Widget screen) => Navigator.of(context)
      .push(MaterialPageRoute<void>(builder: (_) => screen))
      .then((_) => mounted ? _load() : null);

  Future<void> _remove(LocalAccount account) async {
    final services = AppScope.of(context);
    final navigator = Navigator.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Remove ${account.username} from this device?'),
        content: const Text(
          'Signs a one-time unbind request so the server stops accepting '
          'this key, then deletes the key (deleteKeys) and the local '
          'account. Other accounts on this device are not affected.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    final outcome = await services.client.removeFromDevice(account);
    if (!mounted) return;
    if (outcome is Success) {
      navigator.pop();
    } else {
      setState(() => _problem = outcome);
    }
  }

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    return ListenableBuilder(
      listenable: services.accounts,
      builder: (context, _) {
        final account = services.accounts.byAlias(widget.alias);
        if (account == null) {
          return const AppScaffold(
            title: 'Account',
            body: Center(child: Text('This account was removed.')),
          );
        }
        final status = services.accounts.statusOf(account.alias);
        final info = status.health?.info;
        final record = _record;
        final problem = _problem;
        return AppScaffold(
          title: account.username,
          actions: [
            IconButton(
              tooltip: 'Check again',
              onPressed: _loading ? null : _load,
              icon: const Icon(Icons.refresh),
            ),
          ],
          body: PageList(children: [
            if (_loading) const LinearProgressIndicator(),
            SectionCard(
              title: 'Key on this device',
              subtitle: 'getKeyInfo(checkValidity: true)',
              trailing: StatusChip(
                label: status.label,
                kind: status.needsRebind
                    ? StatusKind.danger
                    : status.state == AccountState.ready
                        ? StatusKind.success
                        : StatusKind.neutral,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Explainer(status.message),
                  const SizedBox(height: 8),
                  KeyValueRow(
                      label: 'keyAlias', value: account.alias, monospace: true),
                  KeyValueRow(
                    label: 'exists / isValid',
                    value: info == null
                        ? ''
                        : '${info.exists} / ${info.isValid ?? 'not reported'}',
                    copyable: false,
                  ),
                  KeyValueRow(
                    label: 'Algorithm',
                    value: info?.algorithm == null
                        ? ''
                        : '${info!.algorithm} ${info.keySize ?? ''}'.trim(),
                    copyable: false,
                  ),
                  KeyValueRow(
                    label: 'Registered key SHA-256',
                    value: formatFingerprint(account.publicKeyFingerprint,
                        maxGroups: 8),
                    monospace: true,
                    copyable: false,
                  ),
                  KeyValueRow(
                    label: 'Options',
                    value: [
                      account.allowDeviceCredentials
                          ? 'PIN / passcode allowed'
                          : 'biometric only',
                      account.invalidateOnEnrollment
                          ? 'invalidated by enrollment changes'
                          : 'survives enrollment changes',
                    ].join(' · '),
                    copyable: false,
                  ),
                  if (account.lastAuthenticationType != null)
                    KeyValueRow(
                      label: 'Last authenticationType',
                      value: describeAuthenticationType(
                              account.lastAuthenticationType,
                              platform: services.platform)
                          .toString(),
                      copyable: false,
                    ),
                ],
              ),
            ),
            SectionCard(
              title: 'Server record',
              subtitle: 'POST /devices/status',
              trailing: record == null
                  ? null
                  : StatusChip(
                      label: record.status.name,
                      kind: record.isActive
                          ? StatusKind.success
                          : StatusKind.danger,
                    ),
              child: record == null
                  ? const Explainer('Not available.')
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        KeyValueRow(
                            label: 'userId',
                            value: account.userId,
                            monospace: true),
                        KeyValueRow(
                            label: 'deviceKeyId',
                            value: record.deviceKeyId,
                            monospace: true),
                        KeyValueRow(
                          label: 'Trust tier',
                          value: record.trustTier.label,
                          copyable: false,
                        ),
                        KeyValueRow(
                          label: 'Signature algorithm',
                          value: record.algorithm.label,
                          copyable: false,
                        ),
                        KeyValueRow(
                          label: 'Declared platform',
                          value: record.platform,
                          copyable: false,
                        ),
                        KeyValueRow(
                          label: 'Sign-ins',
                          value: '${record.loginCount}'
                              '${record.lastAuthenticationType == null ? '' : ' · last authenticationType ${record.lastAuthenticationType} (client-reported)'}',
                          copyable: false,
                        ),
                        const SizedBox(height: 8),
                        Align(
                          alignment: Alignment.centerLeft,
                          child: OutlinedButton.icon(
                            onPressed: () => _open(
                                AttestationReportScreen(report: record.report)),
                            icon: const Icon(Icons.verified_user_outlined),
                            label: const Text('View attestation report'),
                          ),
                        ),
                      ],
                    ),
            ),
            if (problem != null)
              OutcomeView(
                outcome: problem,
                onRetry: () => _remove(account),
                onRebind: () => _open(RecoveryScreen(account: account)),
              ),
            if (problem is NeedsRebind)
              OutlinedButton(
                onPressed: () async {
                  final navigator = Navigator.of(context);
                  await services.client.forgetLocally(account);
                  navigator.pop();
                },
                child: const Text('Remove locally only (server record stays '
                    'orphaned)'),
              ),
            Wrap(spacing: 8, runSpacing: 8, children: [
              if (status.needsRebind)
                FilledButton.icon(
                  onPressed: () => _open(RecoveryScreen(account: account)),
                  icon: const Icon(Icons.key),
                  label: const Text('Re-bind this device'),
                )
              else
                FilledButton.icon(
                  onPressed: () => _open(LoginScreen(account: account)),
                  icon: const Icon(Icons.fingerprint),
                  label: const Text('Sign in'),
                ),
              OutlinedButton.icon(
                key: const Key('remove-account'),
                onPressed: () => _remove(account),
                icon: const Icon(Icons.delete_outline),
                label: const Text('Remove from this device'),
              ),
            ]),
          ]),
        );
      },
    );
  }
}
