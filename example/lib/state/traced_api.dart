import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart' show guidanceFor;

import 'call_log.dart';
import 'result_fields.dart';

/// Thrown by [TracedApi] when a plugin call throws. The original error is
/// already in the call log.
class PluginCallException implements Exception {
  /// Wraps [error] thrown by [method].
  const PluginCallException(this.method, this.error);

  /// Plugin method that threw.
  final String method;

  /// The original error.
  final Object error;

  @override
  String toString() => '$method threw: $error';
}

/// [BiometricSignature] with every call recorded in a [CallLog].
///
/// The method signatures mirror [BiometricSignature] exactly, so screens
/// read like ordinary plugin code.
class TracedApi {
  /// Wraps [api], recording into [log].
  TracedApi(this._api, this.log);

  final BiometricSignature _api;

  /// Where calls are recorded.
  final CallLog log;

  Future<T> _trace<T>({
    required String method,
    required String resultType,
    required List<(String, ArgValue)> args,
    required Future<T> Function() run,
  }) async {
    final startedAt = DateTime.now();
    final stopwatch = Stopwatch()..start();
    final snippet = renderDartSnippet(
      method: method,
      resultType: resultType,
      args: args,
    );
    try {
      final result = await run();
      stopwatch.stop();
      final code = resultCode(result);
      log.add(CallLogEntry(
        id: log.nextId(),
        method: method,
        startedAt: startedAt,
        duration: stopwatch.elapsed,
        arguments: flattenArgs(args),
        fields: resultFields(result),
        snippet: snippet,
        code: code,
        error: resultError(result),
        transient: code != null && guidanceFor(code).isTransient,
      ));
      return result;
    } catch (e) {
      stopwatch.stop();
      log.add(CallLogEntry(
        id: log.nextId(),
        method: method,
        startedAt: startedAt,
        duration: stopwatch.elapsed,
        arguments: flattenArgs(args),
        fields: const [],
        snippet: snippet,
        exception: '$e',
      ));
      throw PluginCallException(method, e);
    }
  }

  static List<(String, ArgValue)> _args(Map<String, ArgValue?> map) => [
        for (final e in map.entries)
          if (e.value != null) (e.key, e.value!),
      ];

  static ArgValue? _str(String? v) => v == null ? null : StringArg(v);

  static ArgValue? _bool(bool? v) => v == null ? null : BoolArg(v);

  static ArgValue? _enum(String type, Enum? v) =>
      v == null ? null : EnumArg(type, v);

  static ArgValue? _bytes(Uint8List? v) => v == null ? null : BytesArg(v);

  /// [CreateKeysConfig] as an [ArgValue].
  static ArgValue? createKeysConfigArg(CreateKeysConfig? c) => c == null
      ? null
      : ObjectArg('CreateKeysConfig', {
          'signatureType': _enum('SignatureType', c.signatureType),
          'enforceBiometric': _bool(c.enforceBiometric),
          'setInvalidatedByBiometricEnrollment':
              _bool(c.setInvalidatedByBiometricEnrollment),
          'useDeviceCredentials': _bool(c.useDeviceCredentials),
          'enableDecryption': _bool(c.enableDecryption),
          'promptSubtitle': _str(c.promptSubtitle),
          'promptDescription': _str(c.promptDescription),
          'cancelButtonText': _str(c.cancelButtonText),
          'failIfExists': _bool(c.failIfExists),
          'requireAuthentication': _bool(c.requireAuthentication),
          'attestationChallenge': _bytes(c.attestationChallenge),
        });

  static ArgValue? _signatureConfigArg(CreateSignatureConfig? c) => c == null
      ? null
      : ObjectArg('CreateSignatureConfig', {
          'promptSubtitle': _str(c.promptSubtitle),
          'promptDescription': _str(c.promptDescription),
          'cancelButtonText': _str(c.cancelButtonText),
          'allowDeviceCredentials': _bool(c.allowDeviceCredentials),
        });

  static ArgValue? _decryptConfigArg(DecryptConfig? c) => c == null
      ? null
      : ObjectArg('DecryptConfig', {
          'promptSubtitle': _str(c.promptSubtitle),
          'promptDescription': _str(c.promptDescription),
          'cancelButtonText': _str(c.cancelButtonText),
          'allowDeviceCredentials': _bool(c.allowDeviceCredentials),
        });

  static ArgValue? _promptConfigArg(SimplePromptConfig? c) => c == null
      ? null
      : ObjectArg('SimplePromptConfig', {
          'subtitle': _str(c.subtitle),
          'description': _str(c.description),
          'cancelButtonText': _str(c.cancelButtonText),
          'allowDeviceCredentials': _bool(c.allowDeviceCredentials),
          'biometricStrength': _enum('BiometricStrength', c.biometricStrength),
        });

  /// See [BiometricSignature.biometricAuthAvailable].
  Future<BiometricAvailability> biometricAuthAvailable() => _trace(
        method: 'biometricAuthAvailable',
        resultType: 'BiometricAvailability',
        args: const [],
        run: _api.biometricAuthAvailable,
      );

  /// See [BiometricSignature.isDeviceLockSet].
  Future<bool> isDeviceLockSet() => _trace(
        method: 'isDeviceLockSet',
        resultType: 'bool',
        args: const [],
        run: _api.isDeviceLockSet,
      );

  /// See [BiometricSignature.createKeys].
  Future<KeyCreationResult> createKeys({
    String? keyAlias,
    CreateKeysConfig? config,
    KeyFormat keyFormat = KeyFormat.base64,
    String? promptMessage,
  }) =>
      _trace(
        method: 'createKeys',
        resultType: 'KeyCreationResult',
        args: _args({
          'keyAlias': _str(keyAlias),
          'config': createKeysConfigArg(config),
          'keyFormat': EnumArg('KeyFormat', keyFormat),
          'promptMessage': _str(promptMessage),
        }),
        run: () => _api.createKeys(
          keyAlias: keyAlias,
          config: config,
          keyFormat: keyFormat,
          promptMessage: promptMessage,
        ),
      );

  /// See [BiometricSignature.createSignature].
  Future<SignatureResult> createSignature({
    required String payload,
    String? keyAlias,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat = SignatureFormat.base64,
    KeyFormat keyFormat = KeyFormat.base64,
    String? promptMessage,
  }) =>
      _trace(
        method: 'createSignature',
        resultType: 'SignatureResult',
        args: _args({
          'payload': StringArg(payload),
          'keyAlias': _str(keyAlias),
          'config': _signatureConfigArg(config),
          'signatureFormat': EnumArg('SignatureFormat', signatureFormat),
          'keyFormat': EnumArg('KeyFormat', keyFormat),
          'promptMessage': _str(promptMessage),
        }),
        run: () => _api.createSignature(
          payload: payload,
          keyAlias: keyAlias,
          config: config,
          signatureFormat: signatureFormat,
          keyFormat: keyFormat,
          promptMessage: promptMessage,
        ),
      );

  /// See [BiometricSignature.createSignatureFromBytes].
  Future<SignatureResult> createSignatureFromBytes({
    required Uint8List payload,
    String? keyAlias,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat = SignatureFormat.base64,
    KeyFormat keyFormat = KeyFormat.base64,
    String? promptMessage,
  }) =>
      _trace(
        method: 'createSignatureFromBytes',
        resultType: 'SignatureResult',
        args: _args({
          'payload': BytesArg(payload),
          'keyAlias': _str(keyAlias),
          'config': _signatureConfigArg(config),
          'signatureFormat': EnumArg('SignatureFormat', signatureFormat),
          'keyFormat': EnumArg('KeyFormat', keyFormat),
          'promptMessage': _str(promptMessage),
        }),
        run: () => _api.createSignatureFromBytes(
          payload: payload,
          keyAlias: keyAlias,
          config: config,
          signatureFormat: signatureFormat,
          keyFormat: keyFormat,
          promptMessage: promptMessage,
        ),
      );

  /// See [BiometricSignature.decrypt].
  Future<DecryptResult> decrypt({
    required String payload,
    required PayloadFormat payloadFormat,
    String? keyAlias,
    DecryptConfig? config,
    String? promptMessage,
  }) =>
      _trace(
        method: 'decrypt',
        resultType: 'DecryptResult',
        args: _args({
          'payload': StringArg(payload),
          'payloadFormat': EnumArg('PayloadFormat', payloadFormat),
          'keyAlias': _str(keyAlias),
          'config': _decryptConfigArg(config),
          'promptMessage': _str(promptMessage),
        }),
        run: () => _api.decrypt(
          payload: payload,
          payloadFormat: payloadFormat,
          keyAlias: keyAlias,
          config: config,
          promptMessage: promptMessage,
        ),
      );

  /// See [BiometricSignature.deleteKeys].
  Future<bool> deleteKeys({String? keyAlias}) => _trace(
        method: 'deleteKeys',
        resultType: 'bool',
        args: _args({'keyAlias': _str(keyAlias)}),
        run: () => _api.deleteKeys(keyAlias: keyAlias),
      );

  /// See [BiometricSignature.deleteAllKeys].
  Future<bool> deleteAllKeys() => _trace(
        method: 'deleteAllKeys',
        resultType: 'bool',
        args: const [],
        run: _api.deleteAllKeys,
      );

  /// See [BiometricSignature.getKeyInfo].
  Future<KeyInfo> getKeyInfo({
    String? keyAlias,
    bool checkValidity = false,
    KeyFormat keyFormat = KeyFormat.base64,
  }) =>
      _trace(
        method: 'getKeyInfo',
        resultType: 'KeyInfo',
        args: _args({
          'keyAlias': _str(keyAlias),
          'checkValidity': BoolArg(checkValidity),
          'keyFormat': EnumArg('KeyFormat', keyFormat),
        }),
        run: () => _api.getKeyInfo(
          keyAlias: keyAlias,
          checkValidity: checkValidity,
          keyFormat: keyFormat,
        ),
      );

  /// See [BiometricSignature.biometricKeyExists].
  Future<bool> biometricKeyExists({
    String? keyAlias,
    bool checkValidity = false,
  }) =>
      _trace(
        method: 'biometricKeyExists',
        resultType: 'bool',
        args: _args({
          'keyAlias': _str(keyAlias),
          'checkValidity': BoolArg(checkValidity),
        }),
        run: () => _api.biometricKeyExists(
          keyAlias: keyAlias,
          checkValidity: checkValidity,
        ),
      );

  /// See [BiometricSignature.simplePrompt].
  Future<SimplePromptResult> simplePrompt({
    required String promptMessage,
    SimplePromptConfig? config,
  }) =>
      _trace(
        method: 'simplePrompt',
        resultType: 'SimplePromptResult',
        args: _args({
          'promptMessage': StringArg(promptMessage),
          'config': _promptConfigArg(config),
        }),
        run: () => _api.simplePrompt(
          promptMessage: promptMessage,
          config: config,
        ),
      );
}
