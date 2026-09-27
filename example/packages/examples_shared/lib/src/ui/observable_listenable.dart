import 'package:flutter/foundation.dart';

import '../server/observable.dart';

/// Bridges the Flutter-free [Observable] to Flutter's [Listenable].
extension ObservableListenable on Observable {
  /// A [Listenable] for `ListenableBuilder` / `AnimatedBuilder`. The same
  /// instance is returned for the same observable.
  Listenable get asListenable => _adapters[this] ??= _ObservableAdapter(this);
}

final Expando<_ObservableAdapter> _adapters = Expando('asListenable');

class _ObservableAdapter implements Listenable {
  _ObservableAdapter(this.source);

  final Observable source;

  @override
  void addListener(VoidCallback listener) => source.addListener(listener);

  @override
  void removeListener(VoidCallback listener) => source.removeListener(listener);
}
