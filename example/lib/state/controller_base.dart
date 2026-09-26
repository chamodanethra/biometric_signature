import 'package:flutter/widgets.dart';

import 'explorer_state.dart';
import 'traced_api.dart';

/// Base class for the per-screen controllers.
///
/// Tracks which operations are running (so buttons show progress and are
/// disabled) and turns unexpected exceptions into [unexpectedError] instead
/// of crashing. Plugin exceptions are already in the call log; any other
/// exception is added to it here.
abstract class ExplorerController extends ChangeNotifier {
  /// Creates the controller.
  ExplorerController(this.state);

  /// Session state.
  final ExplorerState state;

  /// The traced plugin API.
  TracedApi get api => state.api;

  final Set<String> _busy = {};
  bool _disposed = false;

  /// Whether the operation [id] is running.
  bool isBusy(String id) => _busy.contains(id);

  /// Whether any operation is running.
  bool get anyBusy => _busy.isNotEmpty;

  /// The last unexpected exception, shown as a banner.
  String? unexpectedError;

  /// Clears [unexpectedError].
  void dismissUnexpectedError() {
    unexpectedError = null;
    notifyListeners();
  }

  /// Applies [change] and notifies listeners (for form fields).
  void update(VoidCallback change) {
    change();
    notifyListeners();
  }

  /// Runs [body] as operation [id]. Ignored while [id] is already running.
  Future<void> run(String id, Future<void> Function() body) async {
    if (_busy.contains(id)) return;
    _busy.add(id);
    unexpectedError = null;
    notifyListeners();
    try {
      await body();
    } on PluginCallException catch (e) {
      unexpectedError = '$e';
    } catch (e) {
      unexpectedError = '$e';
      state.log.addLocalFailure('Explorer: $id', e);
    } finally {
      _busy.remove(id);
      if (!_disposed) notifyListeners();
    }
  }

  /// `null` for blank text, otherwise the text.
  static String? optionalText(TextEditingController controller) {
    final text = controller.text;
    return text.trim().isEmpty ? null : text;
  }

  @override
  void notifyListeners() {
    if (!_disposed) super.notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}
