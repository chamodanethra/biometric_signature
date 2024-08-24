import 'package:biometric_signature/android_config.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'biometric_signature_method_channel.dart';

abstract class BiometricSignaturePlatform extends PlatformInterface {
  /// Constructs a BiometricSignaturePlatform.
  BiometricSignaturePlatform() : super(token: _token);

  static final Object _token = Object();

  static BiometricSignaturePlatform _instance =
      MethodChannelBiometricSignature();

  /// The default instance of [BiometricSignaturePlatform] to use.
  ///
  /// Defaults to [MethodChannelBiometricSignature].
  static BiometricSignaturePlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [BiometricSignaturePlatform] when
  /// they register themselves.
  static set instance(BiometricSignaturePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> createKeys(AndroidConfig config) {
    throw UnimplementedError('createKeys(AndroidConfig config) has not been implemented.');
  }

  Future<bool?> deleteKeys() {
    throw UnimplementedError('deleteKeys() has not been implemented.');
  }

  Future<String?> biometricAuthAvailable() {
    throw UnimplementedError(
        'biometricAuthAvailable() has not been implemented.');
  }

  Future<String?> createSignature({Map<String, String?>? options}) {
    throw UnimplementedError(
        'createSignature(Map<String, String?>? options) has not been implemented.');
  }

  Future<bool?> biometricKeyExists(bool checkValidity) {
    throw UnimplementedError(
        'biometricKeyExists(bool checkValidity) has not been implemented.');
  }
}
