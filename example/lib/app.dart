import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import 'screens/decrypt_screen.dart';
import 'screens/device_screen.dart';
import 'screens/errors_screen.dart';
import 'screens/inventory_screen.dart';
import 'screens/keys_screen.dart';
import 'screens/prompt_screen.dart';
import 'screens/sign_screen.dart';
import 'state/explorer_state.dart';
import 'version.dart';
import 'widgets/call_log_view.dart';
import 'widgets/form_widgets.dart';

/// Width at which navigation moves from a bottom bar to a side rail.
const double wideLayoutBreakpoint = 840;

/// The Biometric Signature Explorer.
class ExplorerApp extends StatefulWidget {
  /// Creates the app. [api] and [attestationInspector] are injectable for
  /// tests.
  const ExplorerApp({super.key, this.api, this.attestationInspector});

  /// Plugin API (defaults to [BiometricSignature]).
  final BiometricSignature? api;

  /// How attestation chains are inspected (defaults to the shared
  /// verifier against Google's roots, on a background isolate).
  final AttestationInspector? attestationInspector;

  @override
  State<ExplorerApp> createState() => _ExplorerAppState();
}

class _ExplorerAppState extends State<ExplorerApp> {
  late final ExplorerState _state = ExplorerState(
    api: widget.api,
    attestationInspector: widget.attestationInspector,
  );

  @override
  void initState() {
    super.initState();
    _state.device.refresh();
  }

  @override
  void dispose() {
    _state.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ExplorerScope(
      state: _state,
      child: MaterialApp(
        title: 'Biometric Signature Explorer',
        debugShowCheckedModeBanner: false,
        theme: buildExampleTheme(
            seed: Colors.indigo, brightness: Brightness.light),
        darkTheme:
            buildExampleTheme(seed: Colors.indigo, brightness: Brightness.dark),
        themeMode: ThemeMode.system,
        home: const ExplorerHome(),
      ),
    );
  }
}

/// Navigation shell: a bottom bar on narrow screens, a rail on wide ones,
/// and the call log in a bottom sheet.
class ExplorerHome extends StatelessWidget {
  /// Creates the shell.
  const ExplorerHome({super.key});

  static Widget _screenFor(ExplorerDestination d) => switch (d) {
        ExplorerDestination.device => const DeviceScreen(),
        ExplorerDestination.keys => const KeysScreen(),
        ExplorerDestination.sign => const SignScreen(),
        ExplorerDestination.decrypt => const DecryptScreen(),
        ExplorerDestination.inventory => const InventoryScreen(),
        ExplorerDestination.prompt => const PromptScreen(),
        ExplorerDestination.errors => const ErrorsScreen(),
      };

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    return ListenableBuilder(
      listenable: state,
      builder: (context, _) {
        final wide = MediaQuery.sizeOf(context).width >= wideLayoutBreakpoint;
        final destination = state.destination;
        final index = destination.index;
        final body = KeyedSubtree(
          key: ValueKey('screen.${destination.name}'),
          child: _screenFor(destination),
        );
        return DevConsoleScaffold(
          title: Text(destination.title),
          consoleTooltip: 'Call log',
          consoleIcon: Icons.receipt_long,
          actions: [
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 4),
              child: Center(
                child: StatusChip(
                  label: state.platform.label,
                  kind: StatusKind.info,
                  icon: Icons.devices,
                ),
              ),
            ),
          ],
          consoleTabs: [
            DevConsoleTab(
              label: 'Calls',
              icon: Icons.receipt_long,
              builder: (context) => CallLogView(log: state.log),
            ),
            DevConsoleTab(
              label: 'About',
              icon: Icons.info_outline,
              builder: (context) => const _AboutTab(),
            ),
          ],
          body: wide
              ? Row(
                  children: [
                    LayoutBuilder(
                      // The rail does not scroll by itself; landscape phones
                      // are wide but short.
                      builder: (context, constraints) => SingleChildScrollView(
                        child: ConstrainedBox(
                          constraints:
                              BoxConstraints(minHeight: constraints.maxHeight),
                          child: IntrinsicHeight(
                            child: NavigationRail(
                              selectedIndex: index,
                              labelType: NavigationRailLabelType.all,
                              leading: Padding(
                                padding: const EdgeInsets.only(bottom: 8),
                                child: Text(
                                  'v$pluginVersion',
                                  style: Theme.of(context).textTheme.labelSmall,
                                ),
                              ),
                              onDestinationSelected: (i) =>
                                  state.goTo(ExplorerDestination.values[i]),
                              destinations: [
                                for (final d in ExplorerDestination.values)
                                  NavigationRailDestination(
                                    icon: Icon(d.icon),
                                    selectedIcon: Icon(d.selectedIcon),
                                    label: Text(d.label),
                                  ),
                              ],
                            ),
                          ),
                        ),
                      ),
                    ),
                    const VerticalDivider(width: 1),
                    Expanded(child: body),
                  ],
                )
              : body,
          bottomNavigationBar: wide
              ? null
              : NavigationBar(
                  selectedIndex: index,
                  labelBehavior:
                      NavigationDestinationLabelBehavior.onlyShowSelected,
                  onDestinationSelected: (i) =>
                      state.goTo(ExplorerDestination.values[i]),
                  destinations: [
                    for (final d in ExplorerDestination.values)
                      NavigationDestination(
                        icon: Icon(d.icon),
                        selectedIcon: Icon(d.selectedIcon),
                        label: d.label,
                        tooltip: d.title,
                      ),
                  ],
                ),
        );
      },
    );
  }
}

class _AboutTab extends StatelessWidget {
  const _AboutTab();

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    final caps = state.capabilities;
    return ScreenList(
      children: [
        SectionCard(
          title: 'Biometric Signature Explorer',
          subtitle:
              'biometric_signature $pluginVersion · ${state.platform.label}',
          child: const NoteList([
            'Every plugin call made by any screen is in the Calls tab, with '
                'its arguments, every non-null result field and a runnable '
                '"Copy as Dart" snippet.',
            'Local checks (signature verification, attestation inspection) '
                'are demo only — verify on your server. The server must '
                'issue challenges, store the registered public key and check '
                'attestation revocation.',
            'Errors arrive in result.code; the plugin does not throw '
                'PlatformException for them.',
          ]),
        ),
        SectionCard(
          title: 'This platform',
          child: NoteList(caps.notes),
        ),
        const SectionCard(
          title: 'Scenario apps (in the GitHub repository)',
          child: NoteList([
            'passwordless_login — attested device binding and replay-resistant '
                'challenge-response login.',
            'banking_app — step-up transaction signing with a silent device '
                'key and a biometric approval key.',
            'secure_vault — hybrid ECIES / RSA-OAEP encrypted vault.',
          ]),
        ),
      ],
    );
  }
}
