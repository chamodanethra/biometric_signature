import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import 'app_scope.dart';
import 'screens/accounts_screen.dart';

/// The Passwordless Login example app.
class PasswordlessApp extends StatelessWidget {
  /// Creates the app over [services].
  const PasswordlessApp({super.key, required this.services});

  /// The wired-up plugin, mock server and client.
  final AppServices services;

  @override
  Widget build(BuildContext context) {
    return AppScope(
      services: services,
      child: MaterialApp(
        title: 'Passwordless Login',
        debugShowCheckedModeBanner: false,
        theme:
            buildExampleTheme(seed: Colors.teal, brightness: Brightness.light),
        darkTheme:
            buildExampleTheme(seed: Colors.teal, brightness: Brightness.dark),
        themeMode: ThemeMode.system,
        home: const AccountsScreen(),
      ),
    );
  }
}
