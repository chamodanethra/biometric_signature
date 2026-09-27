import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';
import 'package:flutter/foundation.dart';

import '../models/sealed_item.dart';
import '../models/vault_key_record.dart';

/// Device-side storage: sealed items (ciphertext + clear metadata), the
/// registered key record, the device id and settings.
///
/// Nothing stored here can reveal a secret without the vault key.
class VaultRepository extends ChangeNotifier {
  /// Creates a repository over [store] (`client.` prefix in the app).
  VaultRepository(this.store);

  /// Persistence.
  final KeyValueStore store;

  static const String _itemsKey = 'items';
  static const String _keyRecordKey = 'vault_key';
  static const String _deviceIdKey = 'device_id';
  static const String _settingsKey = 'settings';

  List<SealedItem> _items = [];
  VaultKeyRecord? _keyRecord;
  String _deviceId = '';
  bool _hideTitles = false;
  int _skipped = 0;

  /// Items, newest first.
  List<SealedItem> get items => List.unmodifiable(_items);

  /// The registered key, if any.
  VaultKeyRecord? get keyRecord => _keyRecord;

  /// This installation's id at the provisioning server.
  String get deviceId => _deviceId;

  /// "Hide titles until unlocked" (a UI gate, see the vault screen).
  bool get hideTitles => _hideTitles;

  /// Stored entries that could not be parsed on the last [load].
  int get skippedEntries => _skipped;

  /// The item with [id], if any.
  SealedItem? byId(String id) {
    for (final item in _items) {
      if (item.id == id) return item;
    }
    return null;
  }

  /// Loads everything from [store].
  Future<void> load() async {
    final list = await store.readList(_itemsKey) ?? const <dynamic>[];
    final loaded = <SealedItem>[];
    _skipped = 0;
    for (final e in list) {
      try {
        loaded.add(SealedItem.fromJson((e as Map).cast<String, dynamic>()));
      } catch (_) {
        _skipped++;
      }
    }
    _items = loaded;
    final record = await store.readMap(_keyRecordKey);
    try {
      _keyRecord = record == null ? null : VaultKeyRecord.fromJson(record);
    } catch (_) {
      _keyRecord = null;
    }
    final id = await store.read(_deviceIdKey);
    if (id is String && id.isNotEmpty) {
      _deviceId = id;
    } else {
      await _newDeviceId();
    }
    final settings = await store.readMap(_settingsKey);
    _hideTitles = settings?['hideTitles'] == true;
    notifyListeners();
  }

  /// Adds (or replaces, by id) an item.
  Future<void> add(SealedItem item) async {
    _items = [item, ..._items.where((i) => i.id != item.id)];
    await _saveItems();
  }

  /// Removes the item with [id].
  Future<void> remove(String id) async {
    _items = _items.where((i) => i.id != id).toList();
    await _saveItems();
  }

  /// Removes every item matching [test]; returns how many.
  Future<int> removeWhere(bool Function(SealedItem item) test) async {
    final before = _items.length;
    _items = _items.where((i) => !test(i)).toList();
    await _saveItems();
    return before - _items.length;
  }

  /// Replaces every server-provisioned item with [fresh].
  Future<void> replaceServerItems(List<SealedItem> fresh) async {
    _items = [
      ...fresh,
      ..._items.where((i) => i.origin != ItemOrigin.server),
    ];
    await _saveItems();
  }

  /// Saves (or clears) the registered key record.
  Future<void> saveKeyRecord(VaultKeyRecord? record) async {
    _keyRecord = record;
    if (record == null) {
      await store.remove(_keyRecordKey);
    } else {
      await store.write(_keyRecordKey, record.toJson());
    }
    notifyListeners();
  }

  /// Persists the "hide titles" setting.
  Future<void> setHideTitles(bool value) async {
    _hideTitles = value;
    await store.write(_settingsKey, {'hideTitles': value});
    notifyListeners();
  }

  /// Deletes everything and starts as a new installation.
  Future<void> clear() async {
    await store.clear();
    _items = [];
    _keyRecord = null;
    _hideTitles = false;
    _skipped = 0;
    await _newDeviceId();
    notifyListeners();
  }

  Future<void> _newDeviceId() async {
    _deviceId = 'dev-${toHex(secureRandomBytes(4))}';
    await store.write(_deviceIdKey, _deviceId);
  }

  Future<void> _saveItems() async {
    notifyListeners();
    await store.write(_itemsKey, [for (final i in _items) i.toJson()]);
  }
}
