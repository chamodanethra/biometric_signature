import 'package:flutter/material.dart';

/// One tab of the developer console sheet.
class DevConsoleTab {
  /// Creates a tab.
  const DevConsoleTab({
    required this.label,
    required this.builder,
    this.icon,
  });

  /// Tab label, e.g. `Wire`.
  final String label;

  /// Optional icon.
  final IconData? icon;

  /// Builds the tab content (usually a scroll view).
  final WidgetBuilder builder;
}

/// A [Scaffold] whose app bar has a button that opens a bottom sheet with
/// the given [consoleTabs] (e.g. Wire / Audit / Policy / Faults).
class DevConsoleScaffold extends StatelessWidget {
  /// Creates the scaffold.
  const DevConsoleScaffold({
    super.key,
    required this.title,
    required this.body,
    required this.consoleTabs,
    this.actions = const [],
    this.floatingActionButton,
    this.bottomNavigationBar,
    this.drawer,
    this.consoleIcon = Icons.terminal,
    this.consoleTooltip = 'Server console',
  });

  /// App bar title.
  final Widget title;

  /// Page body.
  final Widget body;

  /// Tabs of the console sheet.
  final List<DevConsoleTab> consoleTabs;

  /// App bar actions before the console button.
  final List<Widget> actions;

  /// Passed to [Scaffold].
  final Widget? floatingActionButton;

  /// Passed to [Scaffold].
  final Widget? bottomNavigationBar;

  /// Passed to [Scaffold].
  final Widget? drawer;

  /// Console button icon.
  final IconData consoleIcon;

  /// Console button tooltip (and sheet title).
  final String consoleTooltip;

  /// Opens the console sheet from anywhere.
  static Future<void> openConsole(
    BuildContext context,
    List<DevConsoleTab> tabs, {
    String title = 'Server console',
  }) {
    return showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      showDragHandle: true,
      builder: (context) => SizedBox(
        height: MediaQuery.sizeOf(context).height * 0.85,
        child: DefaultTabController(
          length: tabs.length,
          child: Column(
            children: [
              Semantics(
                header: true,
                child:
                    Text(title, style: Theme.of(context).textTheme.titleMedium),
              ),
              TabBar(
                isScrollable: tabs.length > 3,
                tabs: [
                  for (final t in tabs)
                    Tab(
                      text: t.label,
                      icon: t.icon == null ? null : Icon(t.icon),
                    ),
                ],
              ),
              Expanded(
                child: TabBarView(
                  children: [
                    for (final t in tabs) Builder(builder: t.builder),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: title,
        actions: [
          ...actions,
          if (consoleTabs.isNotEmpty)
            Builder(
              builder: (context) => IconButton(
                icon: Icon(consoleIcon),
                tooltip: consoleTooltip,
                onPressed: () =>
                    openConsole(context, consoleTabs, title: consoleTooltip),
              ),
            ),
        ],
      ),
      drawer: drawer,
      body: body,
      floatingActionButton: floatingActionButton,
      bottomNavigationBar: bottomNavigationBar,
    );
  }
}
