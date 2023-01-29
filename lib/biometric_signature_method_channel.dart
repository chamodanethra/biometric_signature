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
    final response = await methodChannel.invokeMethod<String>('createKeys');
    return response;
  }
  @override
  Future<bool?> deleteKeys() async {
    return methodChannel.invokeMethod<bool>('deleteKeys');
  }
  @override
  Future<String?> createSignature({Map<String?, String?>? options}) async {
    final response = await methodChannel.invokeMethod<String>('createSignature');
    return response;
  }
  @override
  Future<String?> biometricAuthAvailable() async {
    final response = await methodChannel.invokeMethod<String>('biometricAuthAvailable');
    return response;
  }
  @override
  Future<bool?> biometricKeyExists() async {
    return methodChannel.invokeMethod<bool>('biometricKeyExists');
  }
}
