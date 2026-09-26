import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// Reads a fixture file relative to `test/fixtures/`.
String fixtureText(String relativePath) =>
    File('test/fixtures/$relativePath').readAsStringSync();

/// Reads a JSON fixture relative to `test/fixtures/`.
Map<String, dynamic> fixtureJson(String relativePath) =>
    jsonDecode(fixtureText(relativePath)) as Map<String, dynamic>;

/// Decodes base64 from a JSON fixture value.
Uint8List b64(Object? value) => base64.decode(value! as String);
