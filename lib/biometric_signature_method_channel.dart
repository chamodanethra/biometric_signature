import 'dart:io';

import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'biometric_signature_platform_interface.dart';
import 'signature_options.dart';

/// An implementation of [BiometricSignaturePlatform] that uses method channels.
class MethodChannelBiometricSignature extends BiometricSignaturePlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('biometric_signature');

  @override
  Future<String?> createKeys(
    AndroidConfig androidConfig,
    IosConfig iosConfig,
  ) async {
    try {
      if (Platform.isAndroid) {
        return await methodChannel.invokeMethod<String>('createKeys', {
          'useDeviceCredentials': androidConfig.useDeviceCredentials,
          'useEc': androidConfig.signatureType.isEc,
        });
      } else {
        return await methodChannel.invokeMethod<String>('createKeys', {
          'useDeviceCredentials': iosConfig.useDeviceCredentials,
          'useEc': iosConfig.signatureType.isEc,
        });
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
  Future<String?> createSignature(SignatureOptions options) async {
    try {
      final response = await methodChannel.invokeMethod<String>(
        'createSignature',
        options.toMethodChannelMap(),
      );
      return response;
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
}
