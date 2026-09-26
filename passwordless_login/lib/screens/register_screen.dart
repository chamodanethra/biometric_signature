import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app_scope.dart';
import '../client/aliases.dart';
import '../client/auth_client.dart';
import '../client/outcome.dart';
import '../server/models.dart';
import '../widgets/app_scaffold.dart';
import '../widgets/key_options_card.dart';
import '../widgets/outcome_view.dart';
import 'attestation_report_screen.dart';
import 'preflight_screen.dart';

/// Creates an account: server challenge → attested key → verification.
class RegisterScreen extends StatefulWidget {
  /// Creates the screen.
  const RegisterScreen({super.key});

  @override
  State<RegisterScreen> createState() => _RegisterScreenState();
}

class _RegisterScreenState extends State<RegisterScreen> {
  final _username = TextEditingController();
  final String _alias = newAccountAlias();
  KeyOptions _options = const KeyOptions();
  bool _busy = false;
  String? _step;
  String? _usernameError;
  AuthOutcome<Registration>? _outcome;

  @override
  void dispose() {
    _username.dispose();
    super.dispose();
  }

  Future<void> _register({bool replaceExistingKey = false}) async {
    final name = normalizeUsername(_username.text);
    final problem = usernameProblem(name);
    setState(() => _usernameError = problem);
    if (problem != null) return;
    await _run(() => AppScope.of(context).client.register(
          username: name,
          alias: _alias,
          options: _options,
          replaceExistingKey: replaceExistingKey,
          onProgress: _progress,
        ));
  }

  Future<void> _retryUpload() => _run(
      () => AppScope.of(context).client.retryUpload(onProgress: _progress));

  Future<void> _unlockThenRegister() async {
    final unlocked =
        await AppScope.of(context).client.unlockWithDeviceCredential();
    if (!mounted) return;
    if (unlocked is Success) {
      await _register();
    } else {
      setState(() => _outcome = unlocked.castFailure());
    }
  }

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

  void _openPreflight() => Navigator.of(context)
      .push(MaterialPageRoute<void>(builder: (_) => const PreflightScreen()));

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final caps = services.capabilities;
    final outcome = _outcome;
    return AppScaffold(
      title: 'Create account',
      body: PageList(children: [
        ...platformBanners(context,
            onOpenConsole: () => openServerConsole(context)),
        SectionCard(
          title: 'Account',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                key: const Key('username'),
                controller: _username,
                enabled: !_busy,
                autocorrect: false,
                textInputAction: TextInputAction.done,
                onSubmitted: (_) => _busy ? null : _register(),
                decoration: InputDecoration(
                  labelText: 'Username',
                  helperText: 'Lower-case letters, digits, . _ -',
                  errorText: _usernameError,
                  prefixIcon: const Icon(Icons.person_outline),
                ),
              ),
              const SizedBox(height: 8),
              KeyValueRow(
                label: 'Key alias on this device',
                value: _alias,
                monospace: true,
                copyable: false,
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
        SectionCard(
          title: 'What happens',
          child: Explainer(
            '1. The server issues a single-use 32-byte challenge bound to '
            'your username (POST /register/begin).\n'
            '2. createKeys makes a key under $_alias with signatureType: '
            'ecdsa, failIfExists: true and enforceBiometric: true'
            '${caps.supportsAttestation ? ', passing the challenge as attestationChallenge' : ''}. '
            '${services.platform.isApple ? 'On Apple it lives in the Secure Enclave. ' : ''}'
            '${services.platform == DevicePlatform.windows ? 'Windows Hello makes an RSA-2048 key. ' : ''}\n'
            '3. The server checks the certificate chain up to Google’s roots, '
            'the challenge, the public key, the app package and the security '
            'level, then assigns a trust tier (POST /register/finish).\n'
            '4. You get a one-time recovery code for re-binding later.',
          ),
        ),
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
              _ => _register,
            },
            onReplaceKey: () => _register(replaceExistingKey: true),
            onPreflight: _openPreflight,
            onUnlock: _unlockThenRegister,
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
          key: const Key('register-submit'),
          onPressed: _busy ? null : _register,
          icon: const Icon(Icons.fingerprint),
          label: const Text('Create account'),
        ),
      ]),
    );
  }
}
