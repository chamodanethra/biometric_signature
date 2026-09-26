import 'dart:async';
import 'dart:convert';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/reveal_service.dart';
import '../client/vault_controller.dart';
import '../models/sealed_item.dart';
import '../widgets/common.dart';
import 'key_status_screen.dart';

const String _envelopeNote = "decrypt() returned the envelope's data key; "
    'AES-256-GCM opened the content in Dart. ';

/// How long a revealed secret stays on screen.
const Duration revealDuration = Duration(seconds: 30);

/// One item: metadata, ciphertext, and Reveal (the cryptographic gate).
class ItemScreen extends StatefulWidget {
  /// Creates the screen for the item with [itemId].
  const ItemScreen({super.key, required this.itemId});

  /// Item id.
  final String itemId;

  @override
  State<ItemScreen> createState() => _ItemScreenState();
}

class _ItemScreenState extends State<ItemScreen> with WidgetsBindingObserver {
  PayloadFormat _format = PayloadFormat.base64;
  Revealed? _revealed;
  RevealOutcome? _failure;
  bool _revealing = false;
  Timer? _timer;
  int _secondsLeft = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Hide the plaintext before the OS snapshots the app for the switcher.
    if ((state == AppLifecycleState.paused ||
            state == AppLifecycleState.hidden) &&
        _revealed != null) {
      setState(_hide);
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _timer?.cancel();
    super.dispose();
  }

  void _hide() {
    _timer?.cancel();
    _timer = null;
    // Dropping the reference is all Dart allows: the string stays in memory
    // until the garbage collector reclaims it.
    _revealed = null;
  }

  void _startCountdown() {
    _timer?.cancel();
    _secondsLeft = revealDuration.inSeconds;
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      setState(() {
        _secondsLeft--;
        if (_secondsLeft <= 0) _hide();
      });
    });
  }

  Future<void> _reveal(SealedItem item) async {
    final controller = AppScope.read(context);
    setState(() {
      _hide();
      _failure = null;
      _revealing = true;
    });
    final outcome = await controller.reveal(item, format: _format);
    if (!mounted) return;
    setState(() {
      _revealing = false;
      if (outcome is Revealed) {
        _revealed = outcome;
        _startCountdown();
      } else {
        _failure = outcome;
      }
    });
  }

  Future<void> _delete(SealedItem item) async {
    final navigator = Navigator.of(context);
    final controller = AppScope.read(context);
    final ok = await confirmAction(
      context,
      title: 'Delete this item?',
      message: item.origin == ItemOrigin.server
          ? 'The server will deliver it again on the next sync.'
          : 'This is the only copy.',
      confirmLabel: 'Delete',
    );
    if (!ok) return;
    navigator.pop();
    await controller.deleteItem(item.id);
  }

  Future<void> _sync() async {
    final messenger = ScaffoldMessenger.of(context);
    final result = await AppScope.read(context).syncServerItems();
    if (mounted) setState(() => _failure = null);
    showSnack(
        messenger,
        result.ok
            ? 'Fetched a fresh copy from the server.'
            : 'Sync failed: ${result.error}');
  }

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final item = controller.repo.byId(widget.itemId);
        if (item == null) {
          return Scaffold(
            appBar: AppBar(),
            body: const Center(child: Text('This item no longer exists.')),
          );
        }
        final access = controller.accessFor(item);
        final title = controller.titlesVisible ? item.title : 'Vault item';
        return Scaffold(
          appBar: AppBar(
            title: Text(title),
            actions: [
              IconButton(
                icon: const Icon(Icons.delete_outline),
                tooltip: 'Delete',
                onPressed: () => _delete(item),
              ),
            ],
          ),
          body: PageBody(children: [
            if (!controller.capabilities.supportsDecrypt)
              const CapabilityBanner(
                kind: StatusKind.warning,
                title: 'Revealing is not available here',
                message: 'decrypt() returns notAvailable on Windows.',
              ),
            if (access != ItemAccess.readable)
              _accessBanner(controller, item, access),
            _revealCard(controller, item, access),
            _metadataCard(item),
            _ciphertextCard(item),
          ]),
        );
      },
    );
  }

  Widget _accessBanner(
      VaultController controller, SealedItem item, ItemAccess access) {
    if (access == ItemAccess.awaitingReseal) {
      final keyUsable = controller.keyState == VaultKeyState.healthy;
      return CapabilityBanner(
        kind: StatusKind.warning,
        title: 'Sealed to a key that no longer works',
        message: 'This came from the provisioning server, so it is not lost: '
            '${keyUsable ? 'a sync' : 'after re-provisioning, a sync'} '
            'delivers a copy sealed to the current key.',
        action: keyUsable
            ? FilledButton.tonal(
                onPressed: _sync,
                child: const Text('Sync a fresh copy'),
              )
            : null,
      );
    }
    return CapabilityBanner(
      kind: StatusKind.danger,
      icon: Icons.no_encryption_outlined,
      title: 'Unrecoverable',
      message: 'This was sealed to a vault key that has been invalidated or '
          'deleted, and no other copy exists. No key anywhere can decrypt it: '
          'it is crypto-shredded. You can only delete it.',
      action: OutlinedButton(
        onPressed: () => _delete(item),
        child: const Text('Delete'),
      ),
    );
  }

  Widget _revealCard(
      VaultController controller, SealedItem item, ItemAccess access) {
    final theme = Theme.of(context);
    final revealed = _revealed;
    final canReveal = controller.capabilities.supportsDecrypt &&
        access == ItemAccess.readable &&
        !_revealing;
    final children = <Widget>[];
    if (revealed != null) {
      final auth = describeAuthenticationType(
        revealed.authenticationType,
        platform: controller.platform,
      );
      children.addAll([
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: theme.colorScheme.secondaryContainer,
            borderRadius: BorderRadius.circular(8),
          ),
          // Plain Text, not SelectableText: nothing offers to copy the
          // secret to the clipboard, where it would outlive the 30 seconds.
          child: Text(
            revealed.plaintext,
            key: const ValueKey('plaintext'),
            style: monospaceStyle(context, base: theme.textTheme.bodyLarge)
                .copyWith(color: theme.colorScheme.onSecondaryContainer),
          ),
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(child: Text('Hides in $_secondsLeft s')),
            TextButton.icon(
              onPressed: () => setState(_hide),
              icon: const Icon(Icons.visibility_off_outlined),
              label: const Text('Hide now'),
            ),
          ],
        ),
        KeyValueRow(
            label: 'Authenticated with', value: auth.label, copyable: false),
        Caption(auth.reliability),
        const SizedBox(height: 8),
        Caption(
          '${revealed.viaEnvelope ? _envelopeNote : ''}'
          'The plaintext now sits in app memory (Dart strings cannot be '
          'wiped) until it is hidden and garbage-collected. It is never '
          'written to storage, and it hides when the app goes to the '
          'background.',
        ),
      ]);
    } else {
      children.addAll([
        Text(
          item.format == SealFormat.envelope
              ? 'decrypt(payloadFormat: ${_format.name}) unwraps the data key '
                  'inside secure hardware after the biometric check; the app '
                  'then opens the AES-GCM content.'
              : 'decrypt(payloadFormat: ${_format.name}) decrypts inside '
                  'secure hardware after the biometric check. The private key '
                  'never leaves it.',
        ),
        const SizedBox(height: 12),
        Align(
          alignment: Alignment.centerLeft,
          child: FilledButton.icon(
            key: const ValueKey('reveal-button'),
            onPressed: canReveal ? () => _reveal(item) : null,
            icon: const Icon(Icons.fingerprint),
            label: Text(_revealing ? 'Waiting for authentication…' : 'Reveal'),
          ),
        ),
      ]);
    }
    final failure = _failure;
    if (failure != null) {
      children
          .addAll([const SizedBox(height: 12), _failureView(item, failure)]);
    }
    return SectionCard(
      title: 'Reveal',
      subtitle: 'Shown for ${revealDuration.inSeconds} s',
      trailing: const StatusChip(
          label: 'Cryptographic gate', kind: StatusKind.success),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: children,
      ),
    );
  }

  Widget _failureView(SealedItem item, RevealOutcome failure) {
    switch (failure) {
      case RevealFailed() when failure.ciphertextRejected:
        return CapabilityBanner(
          kind: StatusKind.danger,
          title: 'The key is fine; this ciphertext is not',
          message: 'decrypt() failed with ${failure.code.name}, but '
              'getKeyInfo(checkValidity: true) reports a healthy key. The '
              'ciphertext was modified after sealing (every scheme here is '
              'authenticated: GCM tags, OAEP padding checks) or was sealed to '
              'another key. Nothing was revealed.'
              '${failure.message == null ? '' : '\n\nPlugin: ${failure.message}'}',
          action: item.origin == ItemOrigin.server
              ? FilledButton.tonal(
                  onPressed: _sync,
                  child: const Text('Sync a fresh copy'),
                )
              : null,
        );
      case RevealFailed(:final code, :final message):
        final guidance = guidanceFor(code);
        final recreate = guidance.action == RecoveryAction.recreateKey;
        final retry = guidance.isTransient;
        return ErrorBanner(
          guidance: guidance,
          rawMessage: message,
          actionLabel: recreate ? 'Key status & re-provision' : null,
          onAction: recreate
              ? () => unawaited(Navigator.of(context).push(
                  MaterialPageRoute<void>(
                      builder: (context) => const KeyStatusScreen())))
              : retry
                  ? () => _reveal(item)
                  : null,
        );
      case RevealIntegrityFailure(:final reason):
        return CapabilityBanner(
          kind: StatusKind.danger,
          title: 'Integrity check failed',
          message: '$reason decrypt() succeeded (you authenticated), but the '
              'content was rejected, so nothing was shown.',
          action: item.origin == ItemOrigin.server
              ? FilledButton.tonal(
                  onPressed: _sync,
                  child: const Text('Sync a fresh copy'),
                )
              : null,
        );
      case Revealed():
        return const SizedBox.shrink();
    }
  }

  Widget _metadataCard(SealedItem item) {
    return SectionCard(
      title: 'Stored on this device',
      subtitle: 'Metadata is not encrypted; the secret is.',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          KeyValueRow(
            label: 'Origin',
            value: item.from == null
                ? item.origin.label
                : '${item.origin.label} (from ${item.from})',
            copyable: false,
          ),
          KeyValueRow(
              label: 'Format', value: item.format.label, copyable: false),
          KeyValueRow(
              label: 'Scheme', value: item.schemeLabel, copyable: false),
          KeyValueRow(
            label: 'Sealed to key',
            value: shortFingerprint(item.recipientKey),
            monospace: true,
            copyable: false,
          ),
          KeyValueRow(
            label: 'Secret size',
            value: '${item.plaintextBytes} bytes',
            copyable: false,
          ),
          KeyValueRow(
            label: 'Sealed at',
            value: formatTimestamp(item.createdAt),
            copyable: false,
          ),
        ],
      ),
    );
  }

  Widget _ciphertextCard(SealedItem item) {
    final envelope = item.envelope;
    return SectionCard(
      title: 'Ciphertext',
      subtitle: 'Exactly what decrypt() receives',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Align(
            alignment: Alignment.centerLeft,
            child: SegmentedButton<PayloadFormat>(
              segments: const [
                ButtonSegment(
                    value: PayloadFormat.base64, label: Text('base64')),
                ButtonSegment(value: PayloadFormat.hex, label: Text('hex')),
              ],
              selected: {_format},
              onSelectionChanged: (s) => setState(() => _format = s.first),
            ),
          ),
          const SizedBox(height: 8),
          MonoBlock(
            label: envelope == null
                ? 'payload (payloadFormat: ${_format.name})'
                : 'wrapped data key (payloadFormat: ${_format.name})',
            text:
                RevealService.encodePayload(item.devicePayloadBase64, _format),
            maxHeight: 140,
          ),
          if (envelope != null) ...[
            const SizedBox(height: 8),
            Caption('The ${envelope.ciphertext.length - 16}-byte content and '
                'its 16-byte GCM tag never reach the plugin; they are opened '
                'in Dart with the data key decrypt() returns.'),
            const SizedBox(height: 4),
            MonoBlock(
              label: 'AES-256-GCM content + tag (base64)',
              text: base64.encode(envelope.ciphertext),
              maxHeight: 100,
            ),
          ],
        ],
      ),
    );
  }
}
