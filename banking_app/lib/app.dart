/// The app shell: theme, [AppScope] and the onboarding / home switch.
library;

import 'dart:async';

import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import 'screens/home_screen.dart';
import 'screens/onboarding_screen.dart';
import 'services.dart';

/// The app's seed colour (a blue-green, distinct from the other examples).
const Color bankSeedColor = Color(0xFF00838F);

/// Makes [AppServices] available to every screen.
class AppScope extends InheritedWidget {
  /// Creates the scope.
  const AppScope({super.key, required this.services, required super.child});

  /// The services.
  final AppServices services;

  /// The nearest services.
  static AppServices of(BuildContext context) {
    final scope = context.getInheritedWidgetOfExactType<AppScope>();
    assert(scope != null, 'No AppScope above this context');
    return scope!.services;
  }

  @override
  bool updateShouldNotify(AppScope oldWidget) => services != oldWidget.services;
}

/// The Step-up Banking app.
class BankingApp extends StatefulWidget {
  /// Creates the app around [services].
  const BankingApp({super.key, required this.services});

  /// The services (real in `main.dart`, fakes in tests).
  final AppServices services;

  @override
  State<BankingApp> createState() => _BankingAppState();
}

class _BankingAppState extends State<BankingApp> {
  late final AppLifecycleListener _lifecycle;
  bool _wasEnrolled = false;

  /// When the binding goes away (reset, unbind, lost key), screens pushed
  /// on top of home are unwound so onboarding is visible.
  void _onSession() {
    final enrolled = widget.services.session.isEnrolled;
    if (_wasEnrolled && !enrolled) {
      widget.services.navigatorKey.currentState
          ?.popUntil((route) => route.isFirst);
    }
    _wasEnrolled = enrolled;
  }

  @override
  void initState() {
    super.initState();
    widget.services.session.addListener(_onSession);
    // Refresh silently when the app comes back from the background (not
    // after a biometric prompt, which only makes the app inactive).
    _lifecycle = AppLifecycleListener(
        onRestart: () => unawaited(widget.services.session.autoRefresh()));
    unawaited(widget.services.start());
  }

  @override
  void dispose() {
    widget.services.session.removeListener(_onSession);
    _lifecycle.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AppScope(
      services: widget.services,
      child: MaterialApp(
        title: 'Step-up Banking',
        debugShowCheckedModeBanner: false,
        navigatorKey: widget.services.navigatorKey,
        theme: buildExampleTheme(
            seed: bankSeedColor, brightness: Brightness.light),
        darkTheme:
            buildExampleTheme(seed: bankSeedColor, brightness: Brightness.dark),
        themeMode: ThemeMode.system,
        home: const RootGate(),
      ),
    );
  }
}

/// Shows onboarding until the device is bound, then the home screen.
class RootGate extends StatelessWidget {
  /// Creates the gate.
  const RootGate({super.key});

  @override
  Widget build(BuildContext context) {
    final session = AppScope.of(context).session;
    return ListenableBuilder(
      listenable: session,
      builder: (context, _) {
        if (!session.ready) {
          return const Scaffold(
            body: Center(child: CircularProgressIndicator()),
          );
        }
        return session.isEnrolled
            ? const HomeScreen()
            : const OnboardingScreen();
      },
    );
  }
}
