import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'biometric_signature_platform_interface.dart';

/// An implementation of [BiometricSignaturePlatform] that uses method channels.
class MethodChannelBiometricSignature extends BiometricSignaturePlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('biometric_signature');

  @override
  Future<String?> createKeys() async {
    try {
      final response = await methodChannel.invokeMethod<String>('createKeys');
      return response;
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
  Future<String?> createSignature({Map<String?, String?>? options}) async {
    try {
      final response =
          await methodChannel.invokeMethod<String>('createSignature', options);
      return response;
    } on PlatformException {
      rethrow;
    }
  }

  @override
  Future<String?> biometricAuthAvailable() async {
    try {
      final response =
          await methodChannel.invokeMethod<String>('biometricAuthAvailable');
      return response;
    } on PlatformException {
      rethrow;
    }
  }

  @override
  Future<bool?> biometricKeyExists() async {
    try {
      return methodChannel.invokeMethod<bool>('biometricKeyExists');
    } on PlatformException catch (e) {
      debugPrint(e.message);
      return false;
    }
  }
}
