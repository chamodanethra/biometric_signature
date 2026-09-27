import 'dart:async';

import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/vault_controller.dart';
import '../models/sealed_item.dart';
import '../widgets/common.dart';
import 'add_note_screen.dart';
import 'item_screen.dart';
import 'key_status_screen.dart';
import 'server_console_screen.dart';
import 'share_screen.dart';

/// The vault: key state, the UI gate / cryptographic gate contrast, and the
/// sealed items grouped by origin.
class VaultScreen extends StatelessWidget {
  /// Creates the screen.
  const VaultScreen({super.key});

  static Future<void> _push(BuildContext context, Widget screen) =>
      Navigator.of(context)
          .push(MaterialPageRoute<void>(builder: (context) => screen));

  Future<void> _sync(BuildContext context) async {
    final messenger = ScaffoldMessenger.of(context);
    final result = await AppScope.read(context).syncServerItems();
    showSnack(
      messenger,
      result.ok
          ? 'Received ${result.received} server secrets, freshly sealed to '
              'your key.'
          : 'Sync failed: ${result.error}',
    );
  }

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final usable = controller.keyState == VaultKeyState.healthy;
        final items = controller.repo.items;
        List<SealedItem> from(ItemOrigin o) => [
              for (final i in items)
                if (i.origin == o) i
            ];
        final lost = controller.lostItems;
        return DevConsoleScaffold(
          title: const Text('Secure Vault'),
          consoleTabs: serverConsoleTabs(controller),
          actions: [
            IconButton(
              icon: const Icon(Icons.share_outlined),
              tooltip: 'Share',
              onPressed: () => _push(context, const ShareScreen()),
            ),
            IconButton(
              icon: const Icon(Icons.key_outlined),
              tooltip: 'Key status',
              onPressed: () => _push(context, const KeyStatusScreen()),
            ),
          ],
          floatingActionButton: usable
              ? FloatingActionButton.extended(
                  onPressed: () => _push(context, const AddNoteScreen()),
                  icon: const Icon(Icons.note_add_outlined),
                  label: const Text('Add note'),
                )
              : null,
          body: PageBody(children: [
            _KeyCard(controller: controller),
            if (!usable) _ShreddedBanner(controller: controller),
            if (lost.isNotEmpty)
              _LostBanner(controller: controller, count: lost.length),
            _GatesCard(controller: controller),
            _ItemSection(
              controller: controller,
              title: 'From the provisioning server',
              subtitle: 'Sealed by the server to your key. It can seal them '
                  'again for a new key.',
              items: from(ItemOrigin.server),
              empty: "Nothing yet. Sync to receive the server's secrets.",
              trailing: TextButton.icon(
                onPressed: usable ? () => _sync(context) : null,
                icon: const Icon(Icons.sync),
                label: const Text('Sync'),
              ),
            ),
            _ItemSection(
              controller: controller,
              title: 'Your notes',
              subtitle: 'Sealed on this device. No other copy exists.',
              items: from(ItemOrigin.device),
              empty: 'No notes. Add one: sealing needs no prompt.',
            ),
            _ItemSection(
              controller: controller,
              title: 'Shared with you',
              subtitle: 'Sealed by someone else to your vault address.',
              items: from(ItemOrigin.shared),
              empty: 'Nothing shared yet. See Share → Import.',
            ),
          ]),
        );
      },
    );
  }
}

class _KeyCard extends StatelessWidget {
  const _KeyCard({required this.controller});

  final VaultController controller;

  @override
  Widget build(BuildContext context) {
    final record = controller.record;
    if (record == null) return const SizedBox.shrink();
    return SectionCard(
      title: record.scheme.label,
      subtitle: '${controller.platform.label} · ${record.algorithm} '
          '${record.keySize ?? ''}${record.isHybridMode ? ' hybrid' : ''} · '
          'generation ${record.generation}',
      trailing: keyStateChip(controller.keyState),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Caption(record.scheme.description),
          KeyValueRow(
            label: 'Items are sealed to',
            value: shortFingerprint(record.encryptionKeyFingerprint),
            monospace: true,
            copyable: false,
          ),
        ],
      ),
    );
  }
}

class _ShreddedBanner extends StatelessWidget {
  const _ShreddedBanner({required this.controller});

  final VaultController controller;

  Future<void> _reprovision(BuildContext context) async {
    final messenger = ScaffoldMessenger.of(context);
    final ok = await confirmAction(
      context,
      title: 'Re-provision the vault key?',
      message: 'Deletes the old key, creates a new one and registers it. '
          'The server seals its secrets again. Notes and shared items sealed '
          'to the old key stay unreadable forever.',
      confirmLabel: 'Re-provision',
    );
    if (!ok) return;
    final outcome = await controller.reprovision();
    showSnack(
        messenger,
        switch (outcome) {
          Provisioned(:final itemsReceived, :final syncError) =>
            syncError == null
                ? 'New key registered; $itemsReceived server secrets re-sealed.'
                : 'New key registered, but the sync failed: $syncError',
          KeyCreationFailed(:final code) =>
            'Key creation failed: ${guidanceFor(code).title} (${code.name}).',
          RegistrationFailed(:final message) => 'Registration failed: $message',
        });
  }

  @override
  Widget build(BuildContext context) {
    final (title, message) = switch (controller.keyState) {
      VaultKeyState.invalidated => (
          'Vault key invalidated: everything sealed to it is shredded',
          'A fingerprint or face was added or removed, so the platform '
              'permanently disabled the vault key '
              '(setInvalidatedByBiometricEnrollment: true). Nobody can '
              'decrypt what was sealed to it: not you, and not someone who '
              'just enrolled their own biometrics. That is deliberate. '
              'Re-provision to get a new key; the server re-seals its '
              'secrets, but notes that existed only here are gone.'
        ),
      VaultKeyState.missing => (
          'Vault key missing',
          'There is no key under the alias "vault" any more: it was deleted, '
              'or the app data came back from a backup without it (keys never '
              'leave the device). Items sealed to it cannot be opened. '
              'Re-provision to get a new key.'
        ),
      VaultKeyState.replaced => (
          'A different key is on this device',
          'The key under "vault" is not the one registered with the server. '
              'Re-provision to register a fresh key.'
        ),
      VaultKeyState.healthy => ('', ''),
    };
    return CapabilityBanner(
      kind: StatusKind.danger,
      icon: Icons.no_encryption_gmailerrorred_outlined,
      title: title,
      message: message,
      action: FilledButton(
        onPressed: controller.busy == null ? () => _reprovision(context) : null,
        child: Text(controller.busy ?? 'Re-provision'),
      ),
    );
  }
}

class _LostBanner extends StatelessWidget {
  const _LostBanner({required this.controller, required this.count});

  final VaultController controller;
  final int count;

  @override
  Widget build(BuildContext context) {
    return CapabilityBanner(
      kind: StatusKind.warning,
      title: count == 1
          ? '1 item can never be opened'
          : '$count items can never be opened',
      message: 'They were sealed to a vault key that no longer works. No key '
          'anywhere can decrypt them, so keeping them only keeps their '
          'titles.',
      action: OutlinedButton(
        onPressed: () => unawaited(controller.deleteLostItems()),
        child: const Text('Delete them'),
      ),
    );
  }
}

class _GatesCard extends StatelessWidget {
  const _GatesCard({required this.controller});

  final VaultController controller;

  Future<void> _unlock(BuildContext context) async {
    final messenger = ScaffoldMessenger.of(context);
    final result = await controller.unlockTitles();
    if (result.success != true) {
      final g = guidanceFor(result.code);
      showSnack(messenger, '${g.title}: ${g.message}');
    }
  }

  @override
  Widget build(BuildContext context) {
    final hide = controller.repo.hideTitles;
    return SectionCard(
      title: 'Two kinds of gate',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Row(
              children: [
                Flexible(child: Text('Hide titles until unlocked')),
                SizedBox(width: 8),
                StatusChip(label: 'UI gate', kind: StatusKind.warning),
              ],
            ),
            subtitle: const Text('No cryptography: titles are stored in '
                'plain text, and simplePrompt() only decides whether this '
                'screen shows them. Anyone reading app storage sees them.'),
            value: hide,
            onChanged: (v) => unawaited(controller.setHideTitles(v)),
          ),
          if (hide)
            Align(
              alignment: Alignment.centerLeft,
              child: controller.titlesVisible
                  ? TextButton.icon(
                      onPressed: controller.lockTitles,
                      icon: const Icon(Icons.visibility_off_outlined),
                      label: const Text('Hide titles again'),
                    )
                  : FilledButton.tonalIcon(
                      onPressed: () => _unlock(context),
                      icon: const Icon(Icons.visibility_outlined),
                      label: const Text('Show titles (simplePrompt)'),
                    ),
            ),
          const Divider(height: 24),
          const Row(
            children: [
              Icon(Icons.lock_outline),
              SizedBox(width: 12),
              Expanded(child: Text('Reveal an item')),
              StatusChip(label: 'Cryptographic gate', kind: StatusKind.success),
            ],
          ),
          const SizedBox(height: 4),
          const Caption('decrypt() runs with the private key inside secure '
              'hardware, after the biometric check. Without it the '
              'ciphertext stays ciphertext, whatever the app shows.'),
        ],
      ),
    );
  }
}

class _ItemSection extends StatelessWidget {
  const _ItemSection({
    required this.controller,
    required this.title,
    required this.subtitle,
    required this.items,
    required this.empty,
    this.trailing,
  });

  final VaultController controller;
  final String title;
  final String subtitle;
  final List<SealedItem> items;
  final String empty;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    return SectionCard(
      title: title,
      subtitle: subtitle,
      trailing: trailing,
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
      child: items.isEmpty
          ? Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Caption(empty),
            )
          : Column(
              children: [
                for (final item in items)
                  _ItemTile(controller: controller, item: item),
              ],
            ),
    );
  }
}

class _ItemTile extends StatelessWidget {
  const _ItemTile({required this.controller, required this.item});

  final VaultController controller;
  final SealedItem item;

  @override
  Widget build(BuildContext context) {
    final access = controller.accessFor(item);
    final chip = itemAccessChip(access);
    final visible = controller.titlesVisible;
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Icon(switch (access) {
        ItemAccess.readable => Icons.lock_outline,
        ItemAccess.awaitingReseal => Icons.lock_clock_outlined,
        ItemAccess.lost => Icons.no_encryption_outlined,
      }),
      title: Text(visible ? item.title : '••••••••'),
      subtitle: Text(
        '${item.schemeLabel} · ${item.plaintextBytes} bytes · '
        '${item.format.name}'
        '${item.from == null ? '' : ' · from ${item.from}'}',
      ),
      trailing: chip ?? const Icon(Icons.chevron_right),
      onTap: () => unawaited(Navigator.of(context).push(MaterialPageRoute<void>(
        builder: (context) => ItemScreen(itemId: item.id),
      ))),
    );
  }
}
