import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app_scope.dart';
import '../client/accounts.dart';
import '../client/auth_client.dart';
import '../client/outcome.dart';
import '../server/models.dart';
import '../widgets/app_scaffold.dart';
import '../widgets/key_options_card.dart';
import '../widgets/outcome_view.dart';
import 'attestation_report_screen.dart';
import 'preflight_screen.dart';

/// Binds a new key to an existing account with its one-time recovery code
/// ("re-bind"): after `keyInvalidated`, a lost key, or on a new device.
class RecoveryScreen extends StatefulWidget {
  /// Creates the screen.
  const RecoveryScreen({super.key, this.account, this.username});

  /// The local account being re-bound, if any.
  final LocalAccount? account;

  /// Username to prefill when there is no [account].
  final String? username;

  @override
  State<RecoveryScreen> createState() => _RecoveryScreenState();
}

class _RecoveryScreenState extends State<RecoveryScreen> {
  late final _username = TextEditingController(
      text: widget.account?.username ?? widget.username ?? '');
  final _code = TextEditingController();
  late KeyOptions _options = KeyOptions(
    allowDeviceCredentials: widget.account?.allowDeviceCredentials ?? false,
    invalidateOnEnrollment: widget.account?.invalidateOnEnrollment ?? true,
  );
  bool _busy = false;
  String? _step;
  String? _usernameError;
  String? _codeError;
  AuthOutcome<Registration>? _outcome;

  @override
  void dispose() {
    _username.dispose();
    _code.dispose();
    super.dispose();
  }

  Future<void> _recover({bool replaceExistingKey = false}) async {
    final services = AppScope.of(context);
    final name = normalizeUsername(_username.text);
    final code = normalizeRecoveryCode(_code.text);
    setState(() {
      _usernameError = usernameProblem(name);
      _codeError = code.length == 12 ? null : 'The code has 12 characters';
    });
    if (_usernameError != null || _codeError != null) return;
    await _run(() => services.client.recover(
          username: name,
          recoveryCode: code,
          replacing: widget.account,
          options: _options,
          replaceExistingKey: replaceExistingKey,
          onProgress: _progress,
        ));
  }

  Future<void> _retryUpload() => _run(
      () => AppScope.of(context).client.retryUpload(onProgress: _progress));

  void _progress(String step) {
    if (mounted) setState(() => _step = step);
  }

  Future<void> _run(
      Future<AuthOutcome<Registration>> Function() operation) async {
    setState(() {
      _busy = true;
      _outcome = null;
      _step = null;
    });
    final outcome = await operation();
    if (!mounted) return;
    setState(() {
      _busy = false;
      _outcome = outcome;
    });
    if (outcome case Success(:final value)) {
      await Navigator.of(context).pushReplacement(MaterialPageRoute<void>(
        builder: (_) =>
            AttestationReportScreen(report: value.report, registration: value),
      ));
    }
  }

  Future<void> _forget(LocalAccount account) async {
    final services = AppScope.of(context);
    final navigator = Navigator.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Forget ${account.username} on this device?'),
        content: const Text(
          'Deletes the key (deleteKeys) and the local account. The server '
          'record stays and shows up as orphaned in the server console.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Forget'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    await services.client.forgetLocally(account);
    navigator.pop();
  }

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final account = widget.account;
    final outcome = _outcome;
    return AppScaffold(
      title: account == null ? 'Recover an account' : 'Re-bind this device',
      body: PageList(children: [
        SectionCard(
          title: 'Recovery code',
          subtitle: 'Shown once when the account was created',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Explainer(account == null
                  ? 'Binds this device to an existing account. The server '
                      'checks the code, verifies a fresh key attestation, '
                      'retires the account’s old key and issues a new code.'
                  : 'The key for ${account.username} can no longer sign in '
                      '(${services.accounts.statusOf(account.alias).label.toLowerCase()}). '
                      'A new key is created under the same alias '
                      '(${account.alias}); the server verifies its attestation, '
                      'retires the old key and issues a new code.'),
              const SizedBox(height: 12),
              TextField(
                key: const Key('recovery-username'),
                controller: _username,
                enabled: !_busy && account == null,
                autocorrect: false,
                decoration: InputDecoration(
                  labelText: 'Username',
                  errorText: _usernameError,
                  prefixIcon: const Icon(Icons.person_outline),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                key: const Key('recovery-code-input'),
                controller: _code,
                enabled: !_busy,
                autocorrect: false,
                textCapitalization: TextCapitalization.characters,
                decoration: InputDecoration(
                  labelText: 'Recovery code',
                  hintText: 'XXXX-XXXX-XXXX',
                  errorText: _codeError,
                  prefixIcon: const Icon(Icons.password),
                ),
              ),
            ],
          ),
        ),
        KeyOptionsCard(
          options: _options,
          platform: services.platform,
          enabled: !_busy,
          onChanged: (o) => setState(() => _options = o),
        ),
        ...platformBanners(context,
            onOpenConsole: () => openServerConsole(context)),
        if (_busy)
          Row(children: [
            const SizedBox.square(
              dimension: 20,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
            const SizedBox(width: 12),
            Expanded(child: Text(_step ?? 'Working…')),
          ]),
        if (outcome != null)
          OutcomeView(
            outcome: outcome,
            onRetry: switch (outcome) {
              Retryable(retry: RetryKind.reupload) => _retryUpload,
              _ => _recover,
            },
            onReplaceKey: () => _recover(replaceExistingKey: true),
            onPreflight: () => Navigator.of(context).push(
                MaterialPageRoute<void>(
                    builder: (_) => const PreflightScreen())),
            onViewReport: switch (outcome) {
              Rejected(:final report?) => () => Navigator.of(context).push(
                    MaterialPageRoute<void>(
                      builder: (_) => AttestationReportScreen(
                          report: report, rejected: true),
                    ),
                  ),
              _ => null,
            },
          ),
        FilledButton.icon(
          key: const Key('recover-submit'),
          onPressed: _busy ? null : _recover,
          icon: const Icon(Icons.key),
          label: const Text('Bind a new key'),
        ),
        if (account != null)
          TextButton(
            onPressed: _busy ? null : () => _forget(account),
            child: const Text('Lost the code? Forget this account on this '
                'device'),
          ),
      ]),
    );
  }
}
