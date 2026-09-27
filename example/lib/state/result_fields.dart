import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';

/// One non-null field of a plugin result, formatted for display.
class ResultField {
  /// Creates a field.
  const ResultField(this.name, this.value, {this.monospace = false});

  /// Field name as declared on the result class, e.g. `publicKey`.
  final String name;

  /// Full display value.
  final String value;

  /// Whether the value is key/signature material.
  final bool monospace;

  /// The value shortened to [max] characters for compact lists.
  String preview([int max = 160]) {
    final oneLine = value.replaceAll('\n', ' ');
    if (oneLine.length <= max) return oneLine;
    return '${oneLine.substring(0, max - 1)}… (${value.length} chars)';
  }

  @override
  String toString() => '$name: $value';
}

/// `true` for a result code that means success (`null` counts: results
/// without a `code` field succeeded).
bool isSuccessCode(BiometricError? code) =>
    code == null || code == BiometricError.success;

/// `"<n> bytes"` plus a hex preview of the first [previewBytes] bytes.
String describeBytes(List<int> bytes, {int previewBytes = 24}) {
  if (bytes.isEmpty) return '0 bytes';
  final shown = bytes.length <= previewBytes
      ? toHex(bytes)
      : '${toHex(bytes.sublist(0, previewBytes))}…';
  return '${bytes.length} bytes · $shown';
}

/// The full hex of [bytes] with a length prefix.
String bytesWithHex(List<int> bytes) =>
    '${bytes.length} bytes\n${toHex(bytes)}';

/// Describes an attestation chain field.
String describeChain(List<Uint8List> chain) {
  final sizes = chain.map((c) => '${c.length}').join(' + ');
  return '${chain.length} certificate${chain.length == 1 ? '' : 's'} '
      '(DER, leaf first; $sizes bytes)';
}

/// Every non-null field of a plugin result, in declaration order.
///
/// Supports every result type the plugin returns, plus `bool` (deleteKeys,
/// deleteAllKeys, biometricKeyExists, isDeviceLockSet).
List<ResultField> resultFields(Object? result) {
  final fields = <ResultField>[];
  void add(String name, Object? value, {bool mono = false}) {
    if (value == null) return;
    if (value is Uint8List) {
      fields.add(ResultField(name, bytesWithHex(value), monospace: true));
    } else if (value is Enum) {
      fields.add(ResultField(name, value.name));
    } else {
      fields.add(ResultField(name, '$value', monospace: mono));
    }
  }

  void chain(String name, List<Uint8List>? value) {
    if (value == null) return;
    fields.add(ResultField(name, describeChain(value)));
  }

  switch (result) {
    case final KeyCreationResult r:
      add('code', r.code);
      add('error', r.error);
      add('publicKey', r.publicKey, mono: true);
      add('publicKeyBytes', r.publicKeyBytes);
      add('algorithm', r.algorithm);
      add('keySize', r.keySize);
      add('decryptingPublicKey', r.decryptingPublicKey, mono: true);
      add('decryptingAlgorithm', r.decryptingAlgorithm);
      add('decryptingKeySize', r.decryptingKeySize);
      add('isHybridMode', r.isHybridMode);
      add('authenticationType', r.authenticationType);
      chain('attestationCertificateChain', r.attestationCertificateChain);
    case final SignatureResult r:
      add('code', r.code);
      add('error', r.error);
      add('signature', r.signature, mono: true);
      add('signatureBytes', r.signatureBytes);
      add('publicKey', r.publicKey, mono: true);
      add('algorithm', r.algorithm);
      add('keySize', r.keySize);
      add('authenticationType', r.authenticationType);
    case final DecryptResult r:
      add('code', r.code);
      add('error', r.error);
      add('decryptedData', r.decryptedData, mono: true);
      add('authenticationType', r.authenticationType);
    case final KeyInfo r:
      add('exists', r.exists);
      add('isValid', r.isValid);
      add('algorithm', r.algorithm);
      add('keySize', r.keySize);
      add('isHybridMode', r.isHybridMode);
      add('publicKey', r.publicKey, mono: true);
      add('decryptingPublicKey', r.decryptingPublicKey, mono: true);
      add('decryptingAlgorithm', r.decryptingAlgorithm);
      add('decryptingKeySize', r.decryptingKeySize);
      chain('attestationCertificateChain', r.attestationCertificateChain);
    case final BiometricAvailability r:
      add('canAuthenticate', r.canAuthenticate);
      add('hasEnrolledBiometrics', r.hasEnrolledBiometrics);
      final types = r.availableBiometrics;
      if (types != null) {
        fields.add(ResultField(
          'availableBiometrics',
          types.isEmpty
              ? '[]'
              : '[${types.map((t) => t?.name ?? 'null').join(', ')}]',
        ));
      }
      add('reason', r.reason);
    case final SimplePromptResult r:
      add('success', r.success);
      add('code', r.code);
      add('error', r.error);
      add('authenticationType', r.authenticationType);
    case final bool r:
      add('result', r);
    case null:
      break;
    default:
      add('result', result);
  }
  return fields;
}

/// The `code` of a plugin result, if it has one.
BiometricError? resultCode(Object? result) => switch (result) {
      final KeyCreationResult r => r.code,
      final SignatureResult r => r.code,
      final DecryptResult r => r.code,
      final SimplePromptResult r => r.code,
      _ => null,
    };

/// The `error` message of a plugin result, if it has one.
String? resultError(Object? result) => switch (result) {
      final KeyCreationResult r => r.error,
      final SignatureResult r => r.error,
      final DecryptResult r => r.error,
      final SimplePromptResult r => r.error,
      _ => null,
    };
