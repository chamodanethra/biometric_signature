import 'package:examples_shared/server.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  Future<void> exercise(KeyValueStore store) async {
    expect(await store.read('missing'), isNull);
    await store.write('user', {
      'id': 'u1',
      'devices': [1, 2],
    });
    await store.write('flag', true);
    expect(await store.readMap('user'), {
      'id': 'u1',
      'devices': [1, 2],
    });
    expect(await store.read('flag'), isTrue);
    expect((await store.keys()).toSet(), {'user', 'flag'});
    // Reads are copies.
    final copy = await store.readMap('user');
    copy!['id'] = 'changed';
    expect((await store.readMap('user'))!['id'], 'u1');
    await store.remove('flag');
    expect(await store.keys(), ['user']);
    await store.clear();
    expect(await store.keys(), isEmpty);
  }

  test('InMemoryKeyValueStore', () => exercise(InMemoryKeyValueStore()));

  test('SharedPrefsKeyValueStore is namespaced by prefix', () async {
    SharedPreferences.setMockInitialValues({'other': 'keep'});
    final server = SharedPrefsKeyValueStore('server.');
    final client = SharedPrefsKeyValueStore('client.');
    await client.write('session', {'token': 't'});
    await exercise(server);
    expect(await client.readMap('session'), {'token': 't'});
    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString('other'), 'keep');
    expect(prefs.getString('client.session'), isNotNull);
  });

  test('AuditLog records, persists and reloads', () async {
    final store = InMemoryKeyValueStore();
    final clock = ManualClock(DateTime.utc(2026, 1, 1));
    final log = AuditLog(store: store, clock: clock, maxEntries: 3);
    var notified = 0;
    log.addListener(() => notified++);
    await log.record('server', 'login.ok', severity: AuditSeverity.success);
    await log.record('alice', 'login.rejected',
        detail: 'replayed nonce', severity: AuditSeverity.danger);
    expect(log.entries, hasLength(2));
    expect(log.entries.last.time, DateTime.utc(2026, 1, 1));
    expect(notified, 2);

    final reloaded = AuditLog(store: store);
    await reloaded.load();
    expect(
        reloaded.entries.map((e) => e.event), ['login.ok', 'login.rejected']);
    expect(reloaded.entries.last.severity, AuditSeverity.danger);
    expect(reloaded.entries.last.detail, 'replayed nonce');

    for (var i = 0; i < 5; i++) {
      await log.record('x', 'e$i');
    }
    expect(log.entries, hasLength(3));
    await log.clear();
    expect(log.entries, isEmpty);
    expect(await store.readList('audit_log'), isEmpty);
  });
}
