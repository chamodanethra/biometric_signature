import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/sharing.dart';
import '../models/sealed_item.dart';
import '../widgets/common.dart';

/// Export this vault's address, seal a secret for someone else's vault, or
/// import an item sealed to this one.
class ShareScreen extends StatelessWidget {
  /// Creates the screen. With [senderOnly] (no vault on this device, e.g.
  /// Windows) only sealing for others is offered.
  const ShareScreen({super.key, this.senderOnly = false});

  /// Show only "Seal for someone".
  final bool senderOnly;

  @override
  Widget build(BuildContext context) {
    if (senderOnly) {
      return Scaffold(
        appBar: AppBar(title: const Text('Seal for another vault')),
        body: const _SealTab(),
      );
    }
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Share'),
          bottom: const TabBar(
            tabs: [
              Tab(text: 'My address'),
              Tab(text: 'Seal for someone'),
              Tab(text: 'Import'),
            ],
          ),
        ),
        body: const TabBarView(
          children: [_AddressTab(), _SealTab(), _ImportTab()],
        ),
      ),
    );
  }
}

class _AddressTab extends StatefulWidget {
  const _AddressTab();

  @override
  State<_AddressTab> createState() => _AddressTabState();
}

class _AddressTabState extends State<_AddressTab> {
  Future<VaultAddress>? _address;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _address ??= AppScope.read(context).myAddress();
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<VaultAddress>(
      future: _address,
      builder: (context, snapshot) {
        final address = snapshot.data;
        return PageBody(children: [
          const Text(
            'Your vault address holds only public data: your platform, the '
            'encryption scheme and the public key items are sealed to. '
            'Anyone with it can seal a secret that only this vault can open. '
            'It is built from getKeyInfo(keyFormat: KeyFormat.pem).',
          ),
          if (snapshot.hasError)
            CapabilityBanner(
              kind: StatusKind.danger,
              title: 'No address',
              message: '${snapshot.error}',
            )
          else if (address == null)
            const BusyRow('Reading the key…')
          else ...[
            SectionCard(
              title: address.scheme.label,
              subtitle: address.platform.label,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Caption(address.scheme.description),
                  KeyValueRow(
                    label: 'Fingerprint',
                    value: shortFingerprint(address.fingerprint),
                    monospace: true,
                    copyable: false,
                  ),
                ],
              ),
            ),
            MonoBlock(
              label: 'Vault address (JSON)',
              text: address.encode(),
              maxHeight: 280,
            ),
          ],
        ]);
      },
    );
  }
}

class _SealTab extends StatefulWidget {
  const _SealTab();

  @override
  State<_SealTab> createState() => _SealTabState();
}

class _SealTabState extends State<_SealTab> {
  final _addressText = TextEditingController();
  final _title = TextEditingController();
  final _secret = TextEditingController();
  final _from = TextEditingController();
  VaultAddress? _to;
  String? _error;
  String? _sealed;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_from.text.isEmpty) _from.text = AppScope.read(context).senderLabel;
  }

  @override
  void dispose() {
    _addressText.dispose();
    _title.dispose();
    _secret.dispose();
    _from.dispose();
    super.dispose();
  }

  void _check() {
    setState(() {
      _sealed = null;
      try {
        _to = VaultAddress.parse(_addressText.text);
        _error = null;
      } on SharingException catch (e) {
        _to = null;
        _error = e.message;
      }
    });
  }

  void _seal() {
    final to = _to;
    if (to == null) return;
    setState(() {
      _sealed = sealForRecipient(
        to,
        title:
            _title.text.trim().isEmpty ? 'Shared secret' : _title.text.trim(),
        secret: _secret.text,
        from: _from.text.trim(),
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    final to = _to;
    final colors = context.statusColors;
    return PageBody(children: [
      const Text(
        "Sealing needs only the recipient's public key: no key of your own "
        'and no prompt. To try it on one device, copy your own address from '
        '"My address" and paste it here.',
      ),
      TextField(
        controller: _addressText,
        decoration: const InputDecoration(
          labelText: "Recipient's vault address (JSON)",
          alignLabelWithHint: true,
        ),
        minLines: 3,
        maxLines: 8,
        onChanged: (_) {
          if (_to != null || _error != null) {
            setState(() {
              _to = null;
              _error = null;
              _sealed = null;
            });
          }
        },
      ),
      Align(
        alignment: Alignment.centerLeft,
        child: FilledButton.tonal(
          onPressed: _check,
          child: const Text('Check address'),
        ),
      ),
      if (_error != null) Text(_error!, style: TextStyle(color: colors.danger)),
      if (to != null) ...[
        SectionCard(
          title: 'Recipient: ${to.label ?? to.platform.label}',
          subtitle: '${to.platform.label} · ${to.scheme.label}',
          trailing:
              const StatusChip(label: 'Consistent', kind: StatusKind.success),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Caption('Scheme re-derived from the platform and key: '
                  '${to.scheme.description}'),
              KeyValueRow(
                label: 'Key fingerprint',
                value: shortFingerprint(to.fingerprint),
                monospace: true,
                copyable: false,
              ),
            ],
          ),
        ),
        TextField(
          controller: _title,
          decoration: const InputDecoration(labelText: 'Title (not encrypted)'),
        ),
        TextField(
          controller: _secret,
          decoration: const InputDecoration(
            labelText: 'Secret',
            alignLabelWithHint: true,
          ),
          minLines: 2,
          maxLines: 8,
        ),
        TextField(
          controller: _from,
          decoration: const InputDecoration(
            labelText: 'From (shown to the recipient, not verified)',
          ),
        ),
        Align(
          alignment: Alignment.centerLeft,
          child: FilledButton.icon(
            onPressed: _seal,
            icon: const Icon(Icons.lock_outline),
            label: const Text('Seal'),
          ),
        ),
      ],
      if (_sealed != null) ...[
        MonoBlock(
          label: 'Sealed item (send this to the recipient)',
          text: _sealed!,
          maxHeight: 280,
        ),
        const Caption("Only the recipient's vault key can open it. The "
            '"from" field is not authenticated: anyone can seal to an '
            'address, so treat shared items like email attachments.'),
      ],
    ]);
  }
}

class _ImportTab extends StatefulWidget {
  const _ImportTab();

  @override
  State<_ImportTab> createState() => _ImportTabState();
}

class _ImportTabState extends State<_ImportTab> {
  final _text = TextEditingController();
  String? _error;

  @override
  void dispose() {
    _text.dispose();
    super.dispose();
  }

  Future<void> _import() async {
    final controller = AppScope.read(context);
    final messenger = ScaffoldMessenger.of(context);
    try {
      final item = await controller.importShared(_text.text);
      _text.clear();
      if (mounted) setState(() => _error = null);
      showSnack(messenger,
          'Imported "${item.title}". It stays ciphertext until you reveal it.');
    } on SharingException catch (e) {
      if (mounted) setState(() => _error = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    return PageBody(children: [
      const Text('Paste a sealed item someone made with your vault address. '
          'It is stored as is; revealing it needs your biometrics.'),
      TextField(
        controller: _text,
        decoration: const InputDecoration(
          labelText: 'Sealed item (JSON)',
          alignLabelWithHint: true,
        ),
        minLines: 3,
        maxLines: 10,
      ),
      Align(
        alignment: Alignment.centerLeft,
        child: FilledButton.icon(
          onPressed: _import,
          icon: const Icon(Icons.move_to_inbox_outlined),
          label: const Text('Import'),
        ),
      ),
      if (_error != null)
        Text(_error!, style: TextStyle(color: context.statusColors.danger)),
    ]);
  }
}
