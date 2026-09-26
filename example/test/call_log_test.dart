import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/biometric_signature_platform_interface.dart';
import 'package:biometric_signature_example/state/call_log.dart';
import 'package:biometric_signature_example/state/result_fields.dart';
import 'package:biometric_signature_example/state/traced_api.dart';
import 'package:examples_shared/testing.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('dartStringLiteral', () {
    test('escapes quotes, dollars, backslashes and control characters', () {
      expect(dartStringLiteral('plain'), "'plain'");
      expect(dartStringLiteral("it's"), r"'it\'s'");
      expect(dartStringLiteral(r'$amount'), r"'\$amount'");
      expect(dartStringLiteral(r'a\b'), r"'a\\b'");
      expect(dartStringLiteral('line1\nline2\t'), r"'line1\nline2\t'");
      expect(dartStringLiteral('\u0001'), r"'\u{1}'");
      expect(dartStringLiteral('Pay €12 🙂'), "'Pay €12 🙂'");
    });
  });

  group('renderDartSnippet', () {
    test('createKeys with a nested config and bytes', () {
      final snippet = renderDartSnippet(
        method: 'createKeys',
        resultType: 'KeyCreationResult',
        args: [
          ('keyAlias', const StringArg('explorer_a')),
          (
            'config',
            TracedApi.createKeysConfigArg(CreateKeysConfig(
              signatureType: SignatureType.ecdsa,
              enforceBiometric: true,
              attestationChallenge: Uint8List.fromList([1, 2, 3]),
            ))!,
          ),
          ('keyFormat', const EnumArg('KeyFormat', KeyFormat.pem)),
          ('promptMessage', const StringArg("Create Bob's key")),
        ],
      );
      expect(snippet, '''
import 'dart:convert';

import 'package:biometric_signature/biometric_signature.dart';

/// Repeats a call made in the Biometric Signature Explorer.
Future<KeyCreationResult> reproduce() {
  return BiometricSignature().createKeys(
    keyAlias: 'explorer_a',
    config: CreateKeysConfig(
      signatureType: SignatureType.ecdsa,
      enforceBiometric: true,
      attestationChallenge: base64.decode('AQID'),
    ),
    keyFormat: KeyFormat.pem,
    promptMessage: 'Create Bob\\'s key',
  );
}
''');
    });

    test('calls without arguments and empty byte payloads', () {
      expect(
        renderDartSnippet(
          method: 'deleteAllKeys',
          resultType: 'bool',
          args: const [],
        ),
        contains('  return BiometricSignature().deleteAllKeys();\n'),
      );
      final empty = renderDartSnippet(
        method: 'createSignatureFromBytes',
        resultType: 'SignatureResult',
        args: [('payload', BytesArg(Uint8List(0)))],
      );
      expect(empty, startsWith("import 'dart:typed_data';\n"));
      expect(empty, contains('payload: Uint8List(0),'));
      expect(empty, isNot(contains('dart:convert')));
    });

    test('flattenArgs expands config objects', () {
      final args = [
        ('keyAlias', const StringArg('a')),
        (
          'config',
          TracedApi.createKeysConfigArg(CreateKeysConfig(failIfExists: true))!,
        ),
      ];
      expect(flattenArgs(args), [
        ('keyAlias', '"a"'),
        ('config.failIfExists', 'true'),
      ]);
    });
  });

  group('TracedApi', () {
    late BiometricSignaturePlatform original;
    late SoftwareBiometricPlatform fake;

    setUp(() {
      original = BiometricSignaturePlatform.instance;
      fake = SoftwareBiometricPlatform();
      BiometricSignaturePlatform.instance = fake;
    });

    tearDown(() => BiometricSignaturePlatform.instance = original);

    test('records arguments, every result field, the code and a snippet',
        () async {
      final log = CallLog();
      final api = TracedApi(BiometricSignature(), log);
      final created = await api.createKeys(
        keyAlias: 'explorer_a',
        config: CreateKeysConfig(
          signatureType: SignatureType.ecdsa,
          enableDecryption: true,
        ),
      );
      expect(created.code, BiometricError.success);
      final entry = log.last!;
      expect(entry.method, 'createKeys');
      expect(entry.outcome, CallOutcome.success);
      expect(entry.arguments, contains(('config.enableDecryption', 'true')));
      final names = entry.fields.map((f) => f.name).toList();
      expect(
          names,
          containsAll(<String>[
            'code',
            'publicKey',
            'publicKeyBytes',
            'algorithm',
            'keySize',
            'decryptingPublicKey',
            'decryptingAlgorithm',
            'decryptingKeySize',
            'isHybridMode',
          ]));
      expect(entry.snippet, contains('enableDecryption: true,'));

      await api.createSignature(payload: 'x', keyAlias: 'nope');
      expect(log.last!.code, BiometricError.keyNotFound);
      expect(log.last!.outcome, CallOutcome.error);

      final exists = await api.biometricKeyExists(keyAlias: 'explorer_a');
      expect(exists, isTrue);
      expect(log.last!.fields.single.value, 'true');
    });

    test('logs exceptions and wraps them', () async {
      final log = CallLog();
      final api = TracedApi(BiometricSignature(), log);
      BiometricSignaturePlatform.instance = _ThrowingPlatform();
      await expectLater(
        api.biometricAuthAvailable(),
        throwsA(isA<PluginCallException>()),
      );
      expect(log.last!.outcome, CallOutcome.exception);
      expect(log.last!.exception, contains('boom'));
    });
  });

  test('resultFields covers every non-null field', () {
    final fields = resultFields(BiometricAvailability(
      canAuthenticate: true,
      hasEnrolledBiometrics: false,
      availableBiometrics: [BiometricType.face, BiometricType.fingerprint],
      reason: 'test',
    ));
    expect(fields.map((f) => '${f.name}=${f.value}'), [
      'canAuthenticate=true',
      'hasEnrolledBiometrics=false',
      'availableBiometrics=[face, fingerprint]',
      'reason=test',
    ]);
  });
}

class _ThrowingPlatform extends SoftwareBiometricPlatform {
  @override
  Future<BiometricAvailability> biometricAuthAvailable() =>
      Future.error(StateError('boom'));
}
