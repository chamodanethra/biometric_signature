import 'dart:async';
import 'dart:convert';

import 'clock.dart';
import 'observable.dart';

/// A mock-server endpoint.
typedef RouteHandler = Future<Map<String, dynamic>> Function(
    Map<String, dynamic> body);

/// Why a [MockTransport.call] failed.
enum TransportErrorKind {
  /// A fault injected with [MockTransport.failNext].
  injected,

  /// No handler is registered for the route.
  unknownRoute,

  /// The handler threw.
  serverError,
}

/// A failed round trip (the equivalent of a network or 5xx error).
class TransportException implements Exception {
  /// Creates the exception.
  const TransportException(this.route, this.kind, this.message);

  /// The route called.
  final String route;

  /// What went wrong.
  final TransportErrorKind kind;

  /// Description.
  final String message;

  @override
  String toString() => 'TransportException($route, ${kind.name}): $message';
}

/// One request/response pair as it crossed the mock wire.
class WireEntry {
  /// Creates an entry.
  WireEntry({
    required this.id,
    required this.timestamp,
    required this.route,
    required this.request,
    this.faults = const [],
  });

  /// Sequence number.
  final int id;

  /// When the request was sent (server clock).
  final DateTime timestamp;

  /// Route, e.g. `/login/finish`.
  final String route;

  /// The JSON body the server received (after any tampering).
  final Map<String, dynamic> request;

  /// The JSON response, once received.
  Map<String, dynamic>? response;

  /// The error, if the call failed.
  String? error;

  /// Round-trip time including simulated latency.
  Duration? elapsed;

  /// Injected faults applied to this call (e.g. `tamper amount`).
  final List<String> faults;

  /// Whether the call failed.
  bool get failed => error != null;

  /// JSON form, e.g. for copying from the UI.
  Map<String, dynamic> toJson() => {
        'id': id,
        'timestamp': timestamp.toIso8601String(),
        'route': route,
        'request': request,
        'response': response,
        'error': error,
        'elapsedMs': elapsed?.inMilliseconds,
        'faults': faults,
      };
}

/// The list of round trips, newest last. Notifies listeners on changes.
class WireLog with Observable {
  /// Creates a log keeping at most [maxEntries].
  WireLog({this.maxEntries = 200});

  /// Maximum number of entries kept.
  final int maxEntries;

  final List<WireEntry> _entries = [];

  /// Entries, oldest first.
  List<WireEntry> get entries => List.unmodifiable(_entries);

  /// Adds an entry.
  void add(WireEntry entry) {
    _entries.add(entry);
    if (_entries.length > maxEntries) _entries.removeAt(0);
    notifyListeners();
  }

  /// Signals that an entry was updated in place.
  void updated() => notifyListeners();

  /// Removes everything.
  void clear() {
    _entries.clear();
    notifyListeners();
  }
}

/// A fault waiting to be applied.
class PendingFault {
  PendingFault._(this.routePattern, this.label, {required this.once});

  /// Route or `prefix*` pattern the fault applies to.
  final String routePattern;

  /// Human-readable description.
  final String label;

  /// Whether the fault is removed after firing once.
  final bool once;

  String? _message;
  String? _fieldPath;
  Object? Function(Object? value)? _mutate;

  bool _matches(String route) => routePattern.endsWith('*')
      ? route.startsWith(routePattern.substring(0, routePattern.length - 1))
      : route == routePattern;
}

/// An in-process "network" between the example apps and their mock server.
///
/// Every call JSON-encodes the request and the response, so only JSON types
/// cross the wire (send bytes as base64 strings). Calls are recorded in
/// [log]. Faults can be injected to show what the server's checks catch:
/// - [failNext]: the next matching call fails before reaching the server;
/// - [tamper]: a field of the next matching request is modified **after**
///   the client built and signed it (a man-in-the-middle);
/// - [replayLast]: re-sends the last request the server received;
/// - clock skew: adjust [Clock.skew] on the client's or server's clock.
class MockTransport with Observable {
  /// Creates a transport. [latency] is simulated per call (use
  /// `Duration.zero` in tests).
  MockTransport({
    this.latency = const Duration(milliseconds: 150),
    WireLog? log,
    Clock? clock,
  })  : log = log ?? WireLog(),
        clock = clock ?? Clock();

  /// Simulated round-trip latency per call.
  Duration latency;

  /// The wire log.
  final WireLog log;

  /// Timestamps for [log].
  final Clock clock;

  final Map<String, RouteHandler> _routes = {};
  final List<PendingFault> _faults = [];
  final Map<String, Map<String, dynamic>> _lastRequest = {};
  int _nextId = 1;

  /// Registers [handler] for [route].
  void register(String route, RouteHandler handler) => _routes[route] = handler;

  /// Registered routes.
  Iterable<String> get routes => _routes.keys;

  /// Faults that have not fired yet.
  List<PendingFault> get pendingFaults => List.unmodifiable(_faults);

  /// Makes the next call matching [routePattern] (exact route, or a prefix
  /// ending in `*`) fail with a [TransportException].
  PendingFault failNext(String routePattern,
      {String message = 'Simulated network failure'}) {
    final fault = PendingFault._(routePattern, 'fail $routePattern', once: true)
      .._message = message;
    _addFault(fault);
    return fault;
  }

  /// Modifies [fieldPath] (dot-separated, list indexes allowed, e.g.
  /// `payload.amount` or `items.0.id`) of the next request matching
  /// [routePattern], after the client produced it. [mutate] receives the
  /// current value and returns the new one; see [Tamper] for helpers.
  PendingFault tamper(
    String routePattern,
    String fieldPath,
    Object? Function(Object? value) mutate, {
    bool once = true,
  }) {
    final fault = PendingFault._(
        routePattern, 'tamper $fieldPath on $routePattern',
        once: once)
      .._fieldPath = fieldPath
      .._mutate = mutate;
    _addFault(fault);
    return fault;
  }

  /// Removes a pending fault.
  void removeFault(PendingFault fault) {
    if (_faults.remove(fault)) notifyListeners();
  }

  /// Removes every pending fault.
  void clearFaults() {
    _faults.clear();
    notifyListeners();
  }

  void _addFault(PendingFault fault) {
    _faults.add(fault);
    notifyListeners();
  }

  /// Whether [route] has a request that [replayLast] can resend.
  bool canReplay(String route) => _lastRequest.containsKey(route);

  /// Re-sends the last request the server received on [route], byte for
  /// byte, as an attacker who captured it would.
  ///
  /// Throws [StateError] if nothing was sent on [route] yet.
  Future<Map<String, dynamic>> replayLast(String route) {
    final last = _lastRequest[route];
    if (last == null) {
      throw StateError('No request on $route to replay');
    }
    return _send(route, _roundTrip(last), faults: ['replay']);
  }

  /// Sends [body] to [route] and returns the decoded response.
  ///
  /// Throws [TransportException] for injected failures, unknown routes and
  /// handler exceptions, and [JsonUnsupportedObjectError] if [body] is not
  /// JSON-encodable.
  Future<Map<String, dynamic>> call(String route, Map<String, dynamic> body) {
    final request = _roundTrip(body);
    final applied = <String>[];
    for (final fault in List.of(_faults)) {
      if (!fault._matches(route)) continue;
      if (fault.once) _faults.remove(fault);
      if (fault._message != null) {
        applied.add(fault.label);
        return _fail(route, request, applied, fault._message!);
      }
      final ok = _applyTamper(request, fault._fieldPath!, fault._mutate!);
      applied.add(ok ? fault.label : '${fault.label} (field not found)');
    }
    if (applied.isNotEmpty) notifyListeners();
    return _send(route, request, faults: applied);
  }

  Future<Map<String, dynamic>> _fail(String route, Map<String, dynamic> request,
      List<String> faults, String message) async {
    notifyListeners();
    final entry = WireEntry(
      id: _nextId++,
      timestamp: clock.now(),
      route: route,
      request: request,
      faults: faults,
    );
    log.add(entry);
    final sw = Stopwatch()..start();
    await _delay();
    entry
      ..error = message
      ..elapsed = sw.elapsed;
    log.updated();
    throw TransportException(route, TransportErrorKind.injected, message);
  }

  Future<Map<String, dynamic>> _send(
    String route,
    Map<String, dynamic> request, {
    List<String> faults = const [],
  }) async {
    final entry = WireEntry(
      id: _nextId++,
      timestamp: clock.now(),
      route: route,
      request: request,
      faults: faults,
    );
    log.add(entry);
    final sw = Stopwatch()..start();
    await _delay();
    final handler = _routes[route];
    if (handler == null) {
      entry
        ..error = 'Unknown route'
        ..elapsed = sw.elapsed;
      log.updated();
      throw TransportException(
          route, TransportErrorKind.unknownRoute, 'Unknown route $route');
    }
    _lastRequest[route] = _roundTrip(request);
    try {
      final response = _roundTrip(await handler(_roundTrip(request)));
      entry
        ..response = response
        ..elapsed = sw.elapsed;
      log.updated();
      return response;
    } catch (e) {
      entry
        ..error = '$e'
        ..elapsed = sw.elapsed;
      log.updated();
      throw TransportException(route, TransportErrorKind.serverError, '$e');
    }
  }

  Future<void> _delay() async {
    if (latency > Duration.zero) await Future<void>.delayed(latency);
  }

  static Map<String, dynamic> _roundTrip(Map<String, dynamic> body) =>
      jsonDecode(jsonEncode(body)) as Map<String, dynamic>;

  static bool _applyTamper(
    Map<String, dynamic> request,
    String path,
    Object? Function(Object? value) mutate,
  ) {
    final parts = path.split('.');
    Object? node = request;
    for (var i = 0; i < parts.length - 1; i++) {
      node = _child(node, parts[i]);
      if (node == null) return false;
    }
    final last = parts.last;
    if (node is Map<String, dynamic> && node.containsKey(last)) {
      node[last] = mutate(node[last]);
      return true;
    }
    final index = int.tryParse(last);
    if (node is List && index != null && index >= 0 && index < node.length) {
      node[index] = mutate(node[index]);
      return true;
    }
    return false;
  }

  static Object? _child(Object? node, String key) {
    if (node is Map<String, dynamic>) return node[key];
    final index = int.tryParse(key);
    if (node is List && index != null && index >= 0 && index < node.length) {
      return node[index];
    }
    return null;
  }
}

/// Ready-made mutations for [MockTransport.tamper].
abstract final class Tamper {
  /// Adds [delta] to an integer field (e.g. an amount in cents).
  static Object? Function(Object?) add(int delta) =>
      (v) => v is int ? v + delta : v;

  /// Replaces the value.
  static Object? Function(Object?) replaceWith(Object? value) => (_) => value;

  /// Flips one bit in the first byte of a base64 field (e.g. a signature).
  static Object? flipBase64Bit(Object? value) {
    if (value is! String || value.isEmpty) return value;
    final bytes = base64.decode(value);
    if (bytes.isEmpty) return value;
    bytes[0] ^= 0x01;
    return base64.encode(bytes);
  }

  /// Appends text to a string field.
  static Object? Function(Object?) appendText(String suffix) =>
      (v) => v is String ? '$v$suffix' : v;
}
