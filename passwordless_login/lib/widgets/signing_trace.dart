import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../client/auth_client.dart';

String _time(DateTime t) {
  final l = t.toLocal();
  String two(int v) => v.toString().padLeft(2, '0');
  return '${two(l.hour)}:${two(l.minute)}:${two(l.second)}';
}

/// Shows each step of a sign-in: the server's nonce, the exact bytes that
/// were signed, the signature, and what the server checked.
class SigningTraceView extends StatelessWidget {
  /// Creates the view.
  const SigningTraceView(
      {super.key, required this.trace, required this.platform});

  /// The trace, updated as the flow runs.
  final LoginTrace trace;

  /// The running platform (for the authenticationType caveat).
  final DevicePlatform platform;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: trace,
      builder: (context, _) {
        final t = trace;
        final payload = t.payloadBytes;
        final authType = describeAuthenticationType(t.authenticationType,
            platform: platform);
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _Step(
              number: 1,
              title: 'Server nonce',
              subtitle: 'POST /login/begin — single use, bound to the user',
              done: t.challengeId != null,
              children: [
                KeyValueRow(
                    label: 'challengeId',
                    value: t.challengeId ?? '',
                    monospace: true),
                KeyValueRow(
                    label: 'nonce (32 bytes)',
                    value: t.nonce ?? '',
                    monospace: true),
                KeyValueRow(
                    label: 'userId', value: t.userId ?? '', monospace: true),
                if (t.expiresAt != null)
                  KeyValueRow(
                      label: 'Expires (server clock)',
                      value: _time(t.expiresAt!),
                      copyable: false),
              ],
            ),
            _Step(
              number: 2,
              title: 'Key on this device',
              subtitle: t.restored
                  ? 'Found among the aliases the server lists for this user'
                  : 'This account’s own alias',
              done: t.alias != null,
              children: [
                KeyValueRow(
                    label: 'keyAlias', value: t.alias ?? '', monospace: true),
                KeyValueRow(
                    label: 'deviceKeyId',
                    value: t.deviceKeyId ?? '',
                    monospace: true),
              ],
            ),
            _Step(
              number: 3,
              title: 'Signed payload',
              subtitle: 'Canonical JSON (sorted keys, no spaces) passed to '
                  'createSignatureFromBytes',
              done: payload != null,
              children: [
                if (t.payloadJson != null)
                  MonoBlock(label: 'UTF-8 payload', text: t.payloadJson!),
                if (payload != null)
                  KeyValueRow(
                    label: 'SHA-256 (${payload.length} bytes)',
                    value: sha256Hex(payload),
                    monospace: true,
                  ),
                const Padding(
                  padding: EdgeInsets.only(top: 4),
                  child: Text(
                    'The "rp" string is chosen by this app, not verified by '
                    'the OS: this proves possession of the key and resists '
                    'replay, but it is not phishing-resistant.',
                  ),
                ),
              ],
            ),
            _Step(
              number: 4,
              title: 'Signature',
              subtitle: 'Made inside secure hardware after the prompt',
              done: t.signature != null,
              children: [
                KeyValueRow(
                  label: 'Algorithm',
                  value: t.algorithm == null
                      ? ''
                      : '${t.algorithm} ${t.keySize ?? ''}'.trim(),
                  copyable: false,
                ),
                if (t.signature != null)
                  MonoBlock(label: 'signature (base64)', text: t.signature!),
                KeyValueRow(
                  label: 'authenticationType',
                  value: t.signature == null ? '' : authType.label,
                  copyable: false,
                ),
                if (t.signature != null) Text(authType.reliability),
              ],
            ),
            _Step(
              number: 5,
              title: 'Server verification',
              subtitle: 'POST /login/finish — nonce consumed first',
              done: t.accepted != null,
              trailing: t.accepted == null
                  ? null
                  : StatusChip(
                      label: t.accepted! ? 'ACCEPTED' : 'REJECTED',
                      kind:
                          t.accepted! ? StatusKind.success : StatusKind.danger,
                    ),
              children: [
                for (final c in t.checks) CheckRow.fromCheck(c),
              ],
            ),
          ],
        );
      },
    );
  }
}

class _Step extends StatelessWidget {
  const _Step({
    required this.number,
    required this.title,
    required this.subtitle,
    required this.done,
    required this.children,
    this.trailing,
  });

  final int number;
  final String title;
  final String subtitle;
  final bool done;
  final List<Widget> children;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: SectionCard(
        title: '$number. $title',
        subtitle: subtitle,
        trailing: trailing ??
            Icon(
              done ? Icons.check_circle : Icons.radio_button_unchecked,
              color: done ? scheme.primary : scheme.outline,
            ),
        child: done
            ? Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: children,
              )
            : Text('Waiting…',
                style: TextStyle(color: scheme.onSurfaceVariant)),
      ),
    );
  }
}
