import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app_scope.dart';
import '../screens/server_console.dart';

/// A page with the server console button in its app bar, so faults can be
/// armed and records inspected from every screen.
class AppScaffold extends StatelessWidget {
  /// Creates the page.
  const AppScaffold({
    super.key,
    required this.title,
    required this.body,
    this.actions = const [],
  });

  /// App bar title.
  final String title;

  /// Content.
  final Widget body;

  /// App bar actions before the console button.
  final List<Widget> actions;

  @override
  Widget build(BuildContext context) {
    return DevConsoleScaffold(
      title: Text(title),
      body: SafeArea(child: body),
      actions: actions,
      consoleTabs: serverConsoleTabs(AppScope.of(context)),
    );
  }
}

/// A scrolling column of cards, centred and width-limited on large screens.
class PageList extends StatelessWidget {
  /// Creates the list.
  const PageList({super.key, required this.children});

  /// Content, spaced vertically.
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: Alignment.topCenter,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 760),
        child: ListView.separated(
          padding: const EdgeInsets.all(16),
          itemCount: children.length,
          separatorBuilder: (_, __) => const SizedBox(height: 12),
          itemBuilder: (_, i) => children[i],
        ),
      ),
    );
  }
}

/// A short, muted explanatory paragraph.
class Explainer extends StatelessWidget {
  /// Creates the text.
  const Explainer(this.text, {super.key});

  /// The text.
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

/// Banners for platforms whose keys cannot be attested, and for Windows'
/// RSA keys. Empty on Android.
List<Widget> platformBanners(BuildContext context,
    {VoidCallback? onOpenConsole}) {
  final services = AppScope.of(context);
  final platform = services.platform;
  final caps = services.capabilities;
  return [
    if (!caps.supportsAttestation)
      CapabilityBanner(
        title: 'Attestation is Android-only',
        message: '${platform.label} cannot prove where a key lives. With '
            '"Require attestation" on (the default), the server rejects this '
            'device — turn it off in the server console to register as '
            'unattested.',
        kind: StatusKind.warning,
        icon: Icons.verified_user_outlined,
        action: onOpenConsole == null
            ? null
            : OutlinedButton.icon(
                onPressed: onOpenConsole,
                icon: const Icon(Icons.terminal),
                label: const Text('Open server console'),
              ),
      ),
    if (platform == DevicePlatform.windows)
      const CapabilityBanner(
        title: 'Windows Hello keys are RSA',
        message: 'Windows ignores signatureType and creates an RSA-2048 key; '
            'the server detects the key type and verifies RSA PKCS#1 v1.5 '
            'signatures. Windows never invalidates keys on enrollment '
            'changes, and authenticationType is always unknown.',
        icon: Icons.window,
      ),
  ];
}

/// Opens the server console sheet.
Future<void> openServerConsole(BuildContext context) =>
    DevConsoleScaffold.openConsole(
        context, serverConsoleTabs(AppScope.of(context)));
