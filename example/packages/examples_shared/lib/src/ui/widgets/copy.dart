import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Copies [text] to the clipboard and shows a short confirmation.
Future<void> copyToClipboard(BuildContext context, String text,
    {String? what}) async {
  await Clipboard.setData(ClipboardData(text: text));
  if (!context.mounted) return;
  ScaffoldMessenger.maybeOf(context)
    ?..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(
      content: Text('${what ?? 'Value'} copied'),
      duration: const Duration(seconds: 2),
    ));
}
