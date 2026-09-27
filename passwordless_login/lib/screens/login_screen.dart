import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app_scope.dart';
import '../client/accounts.dart';
import '../client/auth_client.dart';
import '../client/outcome.dart';
import '../server/models.dart';
import '../widgets/app_scaffold.dart';
import '../widgets/outcome_view.dart';
import '../widgets/signing_trace.dart';
import 'preflight_screen.dart';
import 'recovery_screen.dart';
import 'session_screen.dart';

/// Signs in by signing a server nonce, and shows the signing trace.
///
/// Without an [account], asks for a username and looks for one of that
/// account's keys on this device (e.g. an iOS keychain key that survived a
/// reinstall), restoring the account here.
class LoginScreen extends StatefulWidget {
  /// Creates the screen.
  const LoginScreen({super.key, this.account});

  /// The account to sign in, or `null` to find one by username.
  final LocalAccount? account;

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  late final _username = TextEditingController(text: widget.account?.username);
  LoginTrace? _trace;
  AuthOutcome<SignIn>? _outcome;
  bool _busy = false;
  String? _usernameError;

  @override
  void dispose() {
    _username.dispose();
    super.dispose();
  }

  Future<void> _signIn() async {
    final services = AppScope.of(context);
    final name = normalizeUsername(_username.text);
    final problem = usernameProblem(name);
    final trace = LoginTrace(name);
    setState(() {
      _usernameError = problem;
      if (problem == null) {
        _busy = true;
        _outcome = null;
        _trace = trace;
      }
    });
    if (problem != null) return;
    final outcome = await services.client.login(
      username: name,
      account: widget.account,
      trace: trace,
    );
    if (!mounted) return;
    setState(() {
      _busy = false;
      _outcome = outcome;
    });
  }

  Future<void> _unlockThenSignIn() async {
    final unlocked =
        await AppScope.of(context).client.unlockWithDeviceCredential();
    if (!mounted) return;
    if (unlocked is Success) {
      await _signIn();
    } else {
      setState(() => _outcome = unlocked.castFailure());
    }
  }

  void _open(Widget screen, {bool replace = false}) {
    final route = MaterialPageRoute<void>(builder: (_) => screen);
    final navigator = Navigator.of(context);
    replace ? navigator.pushReplacement(route) : navigator.push(route);
  }

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final account = widget.account;
    final outcome = _outcome;
    final trace = _trace;
    return AppScaffold(
      title: account == null ? 'Sign in to an existing account' : 'Sign in',
      body: PageList(children: [
        if (account == null)
          SectionCard(
            title: 'Find your key',
            subtitle: 'No local account needed',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Explainer(
                  'The server lists the key aliases registered for the '
                  'username. If one of them is still on this device — an iOS '
                  'keychain key survives uninstalling the app, while its '
                  'preferences do not — signing with it restores the account '
                  'here. Otherwise use your recovery code.',
                ),
                const SizedBox(height: 12),
                TextField(
                  key: const Key('login-username'),
                  controller: _username,
                  enabled: !_busy,
                  autocorrect: false,
                  decoration: InputDecoration(
                    labelText: 'Username',
                    errorText: _usernameError,
                    prefixIcon: const Icon(Icons.person_outline),
                  ),
                ),
              ],
            ),
          )
        else
          SectionCard(
            title: account.username,
            subtitle: '${account.alias} · ${account.trustTier.label}',
            child: Explainer(
              'Signing proves this device holds the key registered for '
              '${account.username}. The prompt appears once; nothing but the '
              'signature leaves the device.'
              '${account.allowDeviceCredentials ? ' Your device PIN / passcode is also accepted.' : ''}',
            ),
          ),
        FilledButton.icon(
          key: const Key('sign-in'),
          onPressed: _busy ? null : _signIn,
          icon: const Icon(Icons.fingerprint),
          label: Text(_busy ? 'Signing in…' : 'Sign in'),
        ),
        if (outcome case Success(:final value))
          CapabilityBanner(
            kind: StatusKind.success,
            title: value.restored
                ? 'Signed in — account restored on this device'
                : 'Signed in',
            message: 'The server verified the signature and issued a session.',
            action: FilledButton(
              key: const Key('continue'),
              onPressed: () =>
                  _open(SessionScreen(signIn: value), replace: true),
              child: const Text('Continue'),
            ),
          )
        else if (outcome != null)
          OutcomeView(
            outcome: outcome,
            onRetry: _signIn,
            onUnlock: _unlockThenSignIn,
            onPreflight: () => _open(const PreflightScreen()),
            onRebind: () => _open(
              RecoveryScreen(
                account: outcome is NeedsRebind<SignIn>
                    ? outcome.account ?? account
                    : account,
                username: normalizeUsername(_username.text),
              ),
              replace: true,
            ),
          ),
        if (trace != null)
          SigningTraceView(trace: trace, platform: services.platform),
      ]),
    );
  }
}
