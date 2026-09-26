import 'dart:convert';

import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../models/sealed_item.dart';
import '../widgets/common.dart';

/// Seals a note to the vault's own public key — without any prompt.
class AddNoteScreen extends StatefulWidget {
  /// Creates the screen.
  const AddNoteScreen({super.key});

  @override
  State<AddNoteScreen> createState() => _AddNoteScreenState();
}

class _AddNoteScreenState extends State<AddNoteScreen> {
  final _title = TextEditingController();
  final _body = TextEditingController();
  bool _saving = false;

  @override
  void dispose() {
    _title.dispose();
    _body.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final controller = AppScope.read(context);
    final navigator = Navigator.of(context);
    final messenger = ScaffoldMessenger.of(context);
    setState(() => _saving = true);
    try {
      final item =
          await controller.addNote(title: _title.text, body: _body.text);
      navigator.pop();
      showSnack(
          messenger,
          'Sealed "${item.title}" without a prompt. Reading it back will '
          'need your biometrics.');
    } on StateError catch (e) {
      if (mounted) setState(() => _saving = false);
      showSnack(messenger, e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final scheme = controller.record?.scheme;
    final bytes = utf8.encode(_body.text).length;
    final direct = bytes <= directSealLimit;
    return Scaffold(
      appBar: AppBar(title: const Text('Add a note')),
      body: PageBody(children: [
        const CapabilityBanner(
          icon: Icons.edit_note,
          title: 'Write-only without authentication',
          message: "Sealing needs only the vault's public key, so saving "
              'never prompts and never touches the private key. Reading the '
              'note back needs decrypt() and your biometrics.',
        ),
        TextField(
          controller: _title,
          decoration: const InputDecoration(
            labelText: 'Title',
            helperText: 'Stored in the clear, like every title.',
          ),
          textInputAction: TextInputAction.next,
        ),
        TextField(
          controller: _body,
          decoration: const InputDecoration(
            labelText: 'Secret',
            alignLabelWithHint: true,
          ),
          minLines: 4,
          maxLines: 12,
          onChanged: (_) => setState(() {}),
        ),
        CheckRow(
          kind: StatusKind.info,
          title: direct
              ? '$bytes bytes → sealed directly'
              : '$bytes bytes → envelope',
          detail: direct
              ? 'Fits in one ${scheme?.label ?? ''} ciphertext (up to '
                  '$directSealLimit bytes, the RSA-2048 OAEP limit).'
              : 'Longer than $directSealLimit bytes: the text is encrypted '
                  'with AES-256-GCM under a random data key, and only the '
                  'data key is sealed to the vault key.',
        ),
        const Caption('This note exists only on this device. If the vault key '
            'is ever invalidated, it is gone for good.'),
        Align(
          alignment: Alignment.centerLeft,
          child: FilledButton.icon(
            onPressed: _saving || _body.text.isEmpty ? null : _save,
            icon: const Icon(Icons.lock_outline),
            label: const Text('Seal note'),
          ),
        ),
      ]),
    );
  }
}
