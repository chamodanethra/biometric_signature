import 'package:biometric_signature/ex_map.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'biometric_signature_platform_interface.dart';

/// An implementation of [BiometricSignaturePlatform] that uses method channels.
class MethodChannelBiometricSignature extends BiometricSignaturePlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('biometric_signature');

  @override
  Future<Map<String?, String?>?> createKeys() async {
    final response = await methodChannel.invokeMethod<Map>('createKeys');
    return response.toStringEntriesMap();
  }
  @override
  Future<Map<String?, String?>?> deleteKeys() async {
    final deleted = await methodChannel.invokeMethod<Map<String?, String?>?>('deleteKeys');
    return deleted;
  }
  @override
  Future<Map<String?, String?>?> createSignature({Map<String?, String?>? options}) async {
    final response = await methodChannel.invokeMethod<Map>('createSignature');
    return response.toStringEntriesMap();
  }
  @override
  Future<Map<String?, String?>?> biometricAuthAvailable() async {
    final response = await methodChannel.invokeMethod<Map>('biometricAuthAvailable');
    return response.toStringEntriesMap();
  }
  @override
  Future<Map<String?, String?>?> biometricKeysExist() async {
    final response = await methodChannel.invokeMethod<Map>('biometricKeysExist');
    return response.toStringEntriesMap();
  }
}
