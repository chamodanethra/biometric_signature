/// A minimal, Flutter-free change notifier.
///
/// In Flutter code, wrap it with `observable.asListenable` (from `ui.dart`)
/// to use it with `ListenableBuilder`.
mixin Observable {
  final List<void Function()> _listeners = [];

  /// Registers [listener].
  void addListener(void Function() listener) => _listeners.add(listener);

  /// Unregisters [listener].
  void removeListener(void Function() listener) => _listeners.remove(listener);

  /// Calls every listener.
  void notifyListeners() {
    for (final listener in List.of(_listeners)) {
      listener();
    }
  }
}
