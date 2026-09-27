import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app_scope.dart';
import '../client/auth_client.dart';
import '../widgets/app_scaffold.dart';
import '../widgets/labels.dart';

/// The signed-in state: what the server's session says.
class SessionScreen extends StatelessWidget {
  /// Creates the screen.
  const SessionScreen({super.key, required this.signIn});

  /// The completed sign-in.
  final SignIn signIn;

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final s = signIn.session;
    final a = signIn.account;
    final token = s.token;
    return AppScaffold(
      title: 'Signed in',
      body: PageList(children: [
        CapabilityBanner(
          kind: StatusKind.success,
          icon: Icons.verified,
          title: 'Welcome, ${s.username}',
          message: signIn.restored
              ? 'The key ${a.alias} was already on this device, so the '
                  'account was restored here without a recovery code.'
              : 'The server verified a signature from this device’s key over '
                  'a nonce it issued moments ago.',
        ),
        SectionCard(
          title: 'Session',
          subtitle: 'Issued by the mock server after /login/finish',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              KeyValueRow(label: 'userId', value: s.userId, monospace: true),
              KeyValueRow(
                  label: 'deviceKeyId', value: s.deviceKeyId, monospace: true),
              KeyValueRow(
                label: 'Trust tier',
                value: s.trustTier.label,
                copyable: false,
                trailing: StatusChip(
                    label: s.trustTier.label,
                    kind: statusKindForTier(s.trustTier)),
              ),
              KeyValueRow(
                label: 'Token',
                value: '${token.substring(0, 12)}…',
                monospace: true,
                copyable: false,
              ),
              KeyValueRow(
                label: 'Expires',
                value: s.expiresAt.toLocal().toString(),
                copyable: false,
              ),
              KeyValueRow(
                label: 'authenticationType',
                value: describeAuthenticationType(a.lastAuthenticationType,
                        platform: services.platform)
                    .label,
                copyable: false,
              ),
            ],
          ),
        ),
        SectionCard(
          title: 'What the tier means',
          child: Explainer(tierExplanation(s.trustTier)),
        ),
        const SectionCard(
          title: 'Replay-resistant, not phishing-resistant',
          child: Explainer(
            'Each nonce is single use, expires in minutes and is bound to '
            'one user and purpose, and the server verifies bytes it rebuilt '
            'itself — so a captured request cannot be replayed. But the '
            '"rp" string in the payload is chosen by the app, not checked '
            'by the OS against a web origin: a look-alike app that relays '
            'the server’s nonce could get it signed. This is not FIDO / '
            'WebAuthn / passkeys.',
          ),
        ),
        FilledButton.tonalIcon(
          key: const Key('sign-out'),
          onPressed: () async {
            final navigator = Navigator.of(context);
            await services.client.logout(s);
            navigator.pop();
          },
          icon: const Icon(Icons.logout),
          label: const Text('Sign out'),
        ),
      ]),
    );
  }
}
