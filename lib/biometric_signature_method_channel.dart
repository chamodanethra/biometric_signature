import 'dart:io';

import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'biometric_signature_platform_interface.dart';
import 'decryption_options.dart';
import 'key_material.dart';
import 'signature_options.dart';

/// An implementation of [BiometricSignaturePlatform] that uses method channels.
class MethodChannelBiometricSignature extends BiometricSignaturePlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('biometric_signature');

  @override
  Future<Map<String, dynamic>?> createKeys(
    AndroidConfig androidConfig,
    IosConfig iosConfig, {
    required KeyFormat keyFormat,
    bool enforceBiometric = false,
  }) async {
    try {
      if (Platform.isAndroid) {
        final response = await methodChannel
            .invokeMethod<dynamic>('createKeys', {
              'useDeviceCredentials': androidConfig.useDeviceCredentials,
              'useEc': androidConfig.signatureType.isEc,
              'keyFormat': keyFormat.wireValue,
              'setInvalidatedByBiometricEnrollment':
                  androidConfig.setInvalidatedByBiometricEnrollment,
              'enableDecryption': androidConfig.enableDecryption,
              'enforceBiometric': enforceBiometric,
            });
        return _normalizeMapResponse(response);
      } else {
        final response = await methodChannel
            .invokeMethod<dynamic>('createKeys', {
              'useDeviceCredentials': iosConfig.useDeviceCredentials,
              'useEc': iosConfig.signatureType.isEc,
              'keyFormat': keyFormat.wireValue,
              'biometryCurrentSet': iosConfig.biometryCurrentSet,
              'enforceBiometric': enforceBiometric,
            });
        return _normalizeMapResponse(response);
      }
    } on PlatformException {
      rethrow;
    }
  }

  @override
  Future<bool?> deleteKeys() async {
    try {
      return methodChannel.invokeMethod<bool>('deleteKeys');
    } on PlatformException catch (e) {
      debugPrint(e.message);
      return false;
    }
  }

  @override
  Future<Map<String, dynamic>?> createSignature(
    SignatureOptions options,
  ) async {
    try {
      final response = await methodChannel.invokeMethod<dynamic>(
        'createSignature',
        options.toMethodChannelMap(),
      );
      return _normalizeMapResponse(response);
    } on PlatformException {
      rethrow;
    }
  }

  @override
  Future<Map<String, dynamic>?> decrypt(DecryptionOptions options) async {
    try {
      final response = await methodChannel.invokeMethod<dynamic>(
        'decrypt',
        options.toMethodChannelMap(),
      );
      return _normalizeMapResponse(response);
    } on PlatformException {
      rethrow;
    }
  }

  @override
  Future<String?> biometricAuthAvailable() async {
    try {
      final response = await methodChannel.invokeMethod<String>(
        'biometricAuthAvailable',
      );
      return response;
    } on PlatformException {
      rethrow;
    }
  }

  @override
  Future<bool?> biometricKeyExists(bool checkValidity) async {
    try {
      return methodChannel.invokeMethod<bool>(
        'biometricKeyExists',
        checkValidity,
      );
    } on PlatformException catch (e) {
      debugPrint(e.message);
      return false;
    }
  }

  Map<String, dynamic>? _normalizeMapResponse(dynamic response) {
    if (response == null) {
      return null;
    }
    if (response is Map) {
      return Map<String, dynamic>.from(response);
    }
    throw StateError('Unsupported response type ${response.runtimeType}');
  }
}
