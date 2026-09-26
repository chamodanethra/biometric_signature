import 'dart:io';

import 'package:biometric_signature_example/version.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('pluginVersion matches the plugin pubspec.yaml', () {
    // `flutter test` runs with the example/ directory as the working
    // directory; the plugin's pubspec is one level up.
    final pubspec = File('../pubspec.yaml');
    expect(pubspec.existsSync(), isTrue,
        reason: 'Run the tests from the example/ directory');
    final text = pubspec.readAsStringSync();
    expect(
        RegExp(r'^name:\s*biometric_signature\s*$', multiLine: true)
            .hasMatch(text),
        isTrue);
    final match =
        RegExp(r'^version:\s*(\S+)\s*$', multiLine: true).firstMatch(text);
    expect(match, isNotNull, reason: 'No version: line in ../pubspec.yaml');
    expect(pluginVersion, match!.group(1),
        reason: 'Update lib/version.dart when the plugin version changes');
  });
}
