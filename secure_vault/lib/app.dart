import 'dart:async';

import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import 'client/vault_controller.dart';
import 'screens/setup_screen.dart';
import 'screens/vault_screen.dart';
import 'services.dart';
import 'widgets/common.dart';

/// Gives screens access to the [VaultController].
class AppScope extends InheritedWidget {
  /// Creates the scope.
  const AppScope({super.key, required this.controller, required super.child});

  /// The app state.
  final VaultController controller;

  /// The controller, registering [context] for scope changes.
  static VaultController of(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<AppScope>()!.controller;

  /// The controller, without registering a dependency (for callbacks).
  static VaultController read(BuildContext context) =>
      (context.getElementForInheritedWidgetOfExactType<AppScope>()!.widget
              as AppScope)
          .controller;

  @override
  bool updateShouldNotify(AppScope oldWidget) =>
      controller != oldWidget.controller;
}

/// The Secure Vault app.
class SecureVaultApp extends StatefulWidget {
  /// Creates the app around [services].
  const SecureVaultApp({super.key, required this.services});

  /// Plugin, server, network and storage.
  final AppServices services;

  @override
  State<SecureVaultApp> createState() => _SecureVaultAppState();
}

class _SecureVaultAppState extends State<SecureVaultApp>
    with WidgetsBindingObserver {
  late final VaultController _controller = VaultController(widget.services);
  Object? _startError;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    unawaited(_start());
  }

  Future<void> _start() async {
    try {
      await _controller.start();
    } catch (e) {
      if (mounted) setState(() => _startError = e);
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Titles unlocked with simplePrompt lock again when the app leaves the
    // foreground. (Not on `inactive`: the biometric prompt itself makes the
    // app inactive on iOS.)
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden) {
      _controller.lockTitles();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AppScope(
      controller: _controller,
      child: MaterialApp(
        title: 'Secure Vault',
        debugShowCheckedModeBanner: false,
        theme: buildExampleTheme(
            seed: Colors.deepPurple, brightness: Brightness.light),
        darkTheme: buildExampleTheme(
            seed: Colors.deepPurple, brightness: Brightness.dark),
        themeMode: ThemeMode.system,
        home: _startError == null
            ? const RootScreen()
            : _StartFailed(error: _startError!),
      ),
    );
  }
}

/// Shows setup or the vault, depending on [VaultController.phase].
class RootScreen extends StatelessWidget {
  /// Creates the screen.
  const RootScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) => switch (controller.phase) {
        VaultPhase.loading => const Scaffold(
            body: Center(child: CircularProgressIndicator()),
          ),
        VaultPhase.setup => const SetupScreen(),
        VaultPhase.ready => const VaultScreen(),
      },
    );
  }
}

class _StartFailed extends StatelessWidget {
  const _StartFailed({required this.error});

  final Object error;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Secure Vault')),
      body: PageBody(children: [
        CapabilityBanner(
          kind: StatusKind.danger,
          title: 'The app could not start',
          message: '$error',
        ),
      ]),
    );
  }
}
