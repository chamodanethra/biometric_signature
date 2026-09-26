import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../client/vault_controller.dart';

/// A scrollable page whose content is centred and at most 760 px wide,
/// with a gap between [children].
class PageBody extends StatelessWidget {
  /// Creates the body.
  const PageBody({
    super.key,
    required this.children,
    this.padding = const EdgeInsets.fromLTRB(16, 16, 16, 96),
  });

  /// Sections, top to bottom.
  final List<Widget> children;

  /// Outer padding (the bottom leaves room for a floating button).
  final EdgeInsets padding;

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: Alignment.topCenter,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 760),
        child: ListView.separated(
          padding: padding,
          itemCount: children.length,
          separatorBuilder: (context, index) => const SizedBox(height: 12),
          itemBuilder: (context, index) => children[index],
        ),
      ),
    );
  }
}

/// `2026-09-27 14:03` in local time.
String formatTimestamp(DateTime time) {
  final t = time.toLocal();
  String two(int v) => v.toString().padLeft(2, '0');
  return '${t.year}-${two(t.month)}-${two(t.day)} '
      '${two(t.hour)}:${two(t.minute)}';
}

/// A chip for the vault key's state.
StatusChip keyStateChip(VaultKeyState state) => switch (state) {
      VaultKeyState.healthy =>
        const StatusChip(label: 'Healthy', kind: StatusKind.success),
      VaultKeyState.invalidated =>
        const StatusChip(label: 'Invalidated', kind: StatusKind.danger),
      VaultKeyState.missing =>
        const StatusChip(label: 'Missing', kind: StatusKind.danger),
      VaultKeyState.replaced =>
        const StatusChip(label: 'Not registered', kind: StatusKind.warning),
    };

/// A chip for an item that cannot be opened now, or `null`.
StatusChip? itemAccessChip(ItemAccess access) => switch (access) {
      ItemAccess.readable => null,
      ItemAccess.awaitingReseal =>
        const StatusChip(label: 'Needs re-seal', kind: StatusKind.warning),
      ItemAccess.lost =>
        const StatusChip(label: 'Unrecoverable', kind: StatusKind.danger),
    };

/// Asks for confirmation; returns `true` when confirmed.
Future<bool> confirmAction(
  BuildContext context, {
  required String title,
  required String message,
  required String confirmLabel,
}) async {
  final result = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: Text(title),
      content: Text(message),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: Text(confirmLabel),
        ),
      ],
    ),
  );
  return result ?? false;
}

/// Shows a short message.
void showSnack(ScaffoldMessengerState messenger, String message) {
  messenger
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(message)));
}

/// A line of secondary text.
class Caption extends StatelessWidget {
  /// Creates the caption.
  const Caption(this.text, {super.key});

  /// Text.
  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Text(
      text,
      style: theme.textTheme.bodySmall
          ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
    );
  }
}

/// A busy indicator with a label.
class BusyRow extends StatelessWidget {
  /// Creates the row.
  const BusyRow(this.label, {super.key});

  /// What is happening.
  final String label;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        const SizedBox.square(
          dimension: 20,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
        const SizedBox(width: 12),
        Expanded(child: Text(label)),
      ],
    );
  }
}
