import 'dart:convert';

/// A tiny async JSON key-value store: the mock server's and the client's
/// persistence.
///
/// Values must be JSON-encodable (`null`, `bool`, `num`, `String`, `List`,
/// `Map<String, …>`); they are stored as JSON text, so reads return fresh
/// copies.
abstract class KeyValueStore {
  /// Reads [key], or `null` if absent.
  Future<Object?> read(String key);

  /// Writes [value] under [key].
  Future<void> write(String key, Object? value);

  /// Removes [key].
  Future<void> remove(String key);

  /// All keys.
  Future<List<String>> keys();

  /// Removes every key of this store (only this store's prefix for
  /// prefixed stores).
  Future<void> clear();

  /// Reads a JSON object.
  Future<Map<String, dynamic>?> readMap(String key) async {
    final value = await read(key);
    return value is Map ? value.cast<String, dynamic>() : null;
  }

  /// Reads a JSON array.
  Future<List<dynamic>?> readList(String key) async {
    final value = await read(key);
    return value is List ? value : null;
  }
}

/// A [KeyValueStore] in memory. For tests and ephemeral state.
class InMemoryKeyValueStore extends KeyValueStore {
  final Map<String, String> _data = {};

  @override
  Future<Object?> read(String key) async {
    final raw = _data[key];
    return raw == null ? null : jsonDecode(raw);
  }

  @override
  Future<void> write(String key, Object? value) async =>
      _data[key] = jsonEncode(value);

  @override
  Future<void> remove(String key) async => _data.remove(key);

  @override
  Future<List<String>> keys() async => _data.keys.toList();

  @override
  Future<void> clear() async => _data.clear();
}
