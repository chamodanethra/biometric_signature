import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'biometric_signature_platform_interface.pigeon.dart';

export 'biometric_signature_platform_interface.pigeon.dart';

/// Platform interface that defines the methods exposed to plugin
/// implementations.
abstract class BiometricSignaturePlatform extends PlatformInterface {
  /// Constructs a BiometricSignaturePlatform.
  BiometricSignaturePlatform() : super(token: _token);

  static final Object _token = Object();

  static BiometricSignaturePlatform _instance = _PigeonBiometricSignature();

  /// The default instance of [BiometricSignaturePlatform] to use.
  static BiometricSignaturePlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [BiometricSignaturePlatform] when
  /// they register themselves.
  static set instance(BiometricSignaturePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  /// Checks if biometric authentication is available.
  Future<BiometricAvailability> biometricAuthAvailable() {
    throw UnimplementedError(
      'biometricAuthAvailable() has not been implemented.',
    );
  }

  /// Creates a new key pair.
  Future<KeyCreationResult> createKeys(
    String? keyAlias,
    CreateKeysConfig? config,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    throw UnimplementedError('createKeys() has not been implemented.');
  }

  /// Creates a signature.
  Future<SignatureResult> createSignature(
    String payload,
    String? keyAlias,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    throw UnimplementedError('createSignature() has not been implemented.');
  }

  /// Decrypts data.
  Future<DecryptResult> decrypt(
    String payload,
    String? keyAlias,
    PayloadFormat payloadFormat,
    DecryptConfig? config,
    String? promptMessage,
  ) {
    throw UnimplementedError('decrypt() has not been implemented.');
  }

  /// Deletes keys for a specific alias.
  Future<bool> deleteKeys(String? keyAlias) {
    throw UnimplementedError('deleteKeys() has not been implemented.');
  }

  /// Deletes all biometric keys across all aliases.
  Future<bool> deleteAllKeys() {
    throw UnimplementedError('deleteAllKeys() has not been implemented.');
  }

  /// Gets detailed information about existing biometric keys.
  Future<KeyInfo> getKeyInfo(
    String? keyAlias,
    bool checkValidity,
    KeyFormat keyFormat,
  ) {
    throw UnimplementedError('getKeyInfo() has not been implemented.');
  }

  /// Performs simple biometric authentication without cryptographic operations.
  Future<SimplePromptResult> simplePrompt(
    String promptMessage,
    SimplePromptConfig? config,
  ) {
    throw UnimplementedError('simplePrompt() has not been implemented.');
  }

  /// Checks whether the device has a screen lock configured.
  Future<bool> isDeviceLockSet() {
    throw UnimplementedError('isDeviceLockSet() has not been implemented.');
  }
}

class _PigeonBiometricSignature extends BiometricSignaturePlatform {
  final BiometricSignatureApi _api = BiometricSignatureApi();

  @override
  Future<BiometricAvailability> biometricAuthAvailable() {
    return _api.biometricAuthAvailable();
  }

  @override
  Future<KeyCreationResult> createKeys(
    String? keyAlias,
    CreateKeysConfig? config,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    return _api.createKeys(keyAlias, config, keyFormat, promptMessage);
  }

  @override
  Future<SignatureResult> createSignature(
    String payload,
    String? keyAlias,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    return _api.createSignature(
      payload,
      keyAlias,
      config,
      signatureFormat,
      keyFormat,
      promptMessage,
    );
  }

  @override
  Future<DecryptResult> decrypt(
    String payload,
    String? keyAlias,
    PayloadFormat payloadFormat,
    DecryptConfig? config,
    String? promptMessage,
  ) {
    return _api.decrypt(
      payload,
      keyAlias,
      payloadFormat,
      config,
      promptMessage,
    );
  }

  @override
  Future<bool> deleteKeys(String? keyAlias) {
    return _api.deleteKeys(keyAlias);
  }

  @override
  Future<bool> deleteAllKeys() {
    return _api.deleteAllKeys();
  }

  @override
  Future<KeyInfo> getKeyInfo(
    String? keyAlias,
    bool checkValidity,
    KeyFormat keyFormat,
  ) {
    return _api.getKeyInfo(keyAlias, checkValidity, keyFormat);
  }

  @override
  Future<SimplePromptResult> simplePrompt(
    String promptMessage,
    SimplePromptConfig? config,
  ) {
    return _api.simplePrompt(promptMessage, config);
  }

  @override
  Future<bool> isDeviceLockSet() {
    return _api.isDeviceLockSet();
  }
}
