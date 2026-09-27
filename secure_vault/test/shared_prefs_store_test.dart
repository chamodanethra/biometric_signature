import 'package:flutter_test/flutter_test.dart';
import 'package:secure_vault_example/shared_prefs_store.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  test('SharedPrefsKeyValueStore is namespaced by prefix', () async {
    SharedPreferences.setMockInitialValues({'other': 'keep'});
    final server = SharedPrefsKeyValueStore('server.');
    final client = SharedPrefsKeyValueStore('client.');
    await client.write('session', {'token': 't'});
    await server.write('user', {'id': 'u1'});
    expect(await server.keys(), ['user']);
    expect(await server.readMap('user'), {'id': 'u1'});
    await server.clear();
    expect(await server.keys(), isEmpty);
    expect(await client.readMap('session'), {'token': 't'});
    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString('other'), 'keep');
    expect(prefs.getString('client.session'), isNotNull);
  });
}
