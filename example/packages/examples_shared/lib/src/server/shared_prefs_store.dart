import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import 'key_value_store.dart';

/// A [KeyValueStore] backed by `SharedPreferences`, namespaced by [prefix]
/// (e.g. `server.` for the mock server and `client.` for the app), so
/// "reset demo" can clear one side without touching the other.
///
/// In tests call `SharedPreferences.setMockInitialValues({})` first.
class SharedPrefsKeyValueStore extends KeyValueStore {
  /// Creates a store whose keys are stored as `$prefix$key`.
  SharedPrefsKeyValueStore(this.prefix);

  /// Key prefix.
  final String prefix;

  Future<SharedPreferences> get _prefs => SharedPreferences.getInstance();

  @override
  Future<Object?> read(String key) async {
    final raw = (await _prefs).getString('$prefix$key');
    return raw == null ? null : jsonDecode(raw);
  }

  @override
  Future<void> write(String key, Object? value) async {
    await (await _prefs).setString('$prefix$key', jsonEncode(value));
  }

  @override
  Future<void> remove(String key) async {
    await (await _prefs).remove('$prefix$key');
  }

  @override
  Future<List<String>> keys() async => [
        for (final k in (await _prefs).getKeys())
          if (k.startsWith(prefix)) k.substring(prefix.length),
      ];

  @override
  Future<void> clear() async {
    final prefs = await _prefs;
    for (final k in prefs.getKeys().toList()) {
      if (k.startsWith(prefix)) await prefs.remove(k);
    }
  }
}
