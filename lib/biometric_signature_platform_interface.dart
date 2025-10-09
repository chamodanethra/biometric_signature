import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'biometric_signature_method_channel.dart';
import 'signature_options.dart';

/// Platform interface that defines the methods exposed to plugin
/// implementations.
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

  /// Creates a key pair using the supplied platform-specific configuration.
  Future<String?> createKeys(AndroidConfig androidConfig, IosConfig iosConfig) {
    throw UnimplementedError(
      'createKeys(AndroidConfig androidConfig, IosConfig iosConfig) has not been implemented.',
    );
  }

  /// Deletes the stored biometric key if present.
  Future<bool?> deleteKeys() {
    throw UnimplementedError('deleteKeys() has not been implemented.');
  }

  /// Returns information about the biometric availability on the device.
  Future<String?> biometricAuthAvailable() {
    throw UnimplementedError(
      'biometricAuthAvailable() has not been implemented.',
    );
  }

  /// Creates a signature for the given payload using biometrics.
  Future<String?> createSignature(SignatureOptions options) {
    throw UnimplementedError(
      'createSignature(SignatureOptions options) has not been implemented.',
    );
  }

  /// Checks whether the biometric key exists, optionally validating the key.
  Future<bool?> biometricKeyExists(bool checkValidity) {
    throw UnimplementedError(
      'biometricKeyExists(bool checkValidity) has not been implemented.',
    );
  }
}
