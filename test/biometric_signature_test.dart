import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/biometric_signature_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockBiometricSignaturePlatform
    with MockPlatformInterfaceMixin
    implements BiometricSignaturePlatform {
  String? _authAvailableResult = 'fingerprint';
  bool _shouldThrowError = false;

  void setAuthAvailableResult(String? result) {
    _authAvailableResult = result;
  }

  void setShouldThrowError(bool value) {
    _shouldThrowError = value;
  }

  @override
  Future<String?> biometricAuthAvailable() async {
    if (_shouldThrowError) throw Exception('Auth check failed');
    return Future.value(_authAvailableResult);
  }

  @override
  Future<bool?> biometricKeyExists(bool checkValidity) => Future.value(true);

  @override
  Future<Map<String, dynamic>?> createKeys(
    AndroidConfig androidConfig,
    IosConfig iosConfig, {
    required KeyFormat keyFormat,
    bool enforceBiometric = false,
  }) {
    if (_shouldThrowError) throw Exception('Key creation failed');

    final isEc = androidConfig.signatureType == AndroidSignatureType.ECDSA;
    return Future.value({
      'publicKey': 'test_public_key',
      'publicKeyFormat': keyFormat.wireValue,
      'algorithm': isEc ? 'EC' : 'RSA',
      'keySize': isEc ? 256 : 2048,
    });
  }

  @override
  Future<Map<String, dynamic>?> createSignature(SignatureOptions options) {
    if (_shouldThrowError) throw Exception('Signing failed');

    return Future.value({
      'signature': 'test_signature',
      'signatureFormat': options.keyFormat.wireValue,
      'publicKey': 'test_public_key',
      'publicKeyFormat': options.keyFormat.wireValue,
      'algorithm': 'RSA', // Simplified for mock
      'keySize': 2048,
    });
  }

  @override
  Future<bool?> deleteKeys() => Future.value(true);

  @override
  Future<Map<String, dynamic>?> decrypt(DecryptionOptions options) {
    if (_shouldThrowError) throw Exception('Decryption failed');
    return Future.value({'decryptedData': 'decrypted_${options.payload}'});
  }
}

void main() {
  final BiometricSignaturePlatform initialPlatform =
      BiometricSignaturePlatform.instance;

  test('$BiometricSignaturePlatform is the default instance', () {
    expect(initialPlatform, isInstanceOf<BiometricSignaturePlatform>());
  });

  test('biometricAuthAvailable', () async {
    BiometricSignature biometricSignature = BiometricSignature();
    MockBiometricSignaturePlatform fakePlatform =
        MockBiometricSignaturePlatform();
    BiometricSignaturePlatform.instance = fakePlatform;

    expect(await biometricSignature.biometricAuthAvailable(), 'fingerprint');
  });

  group('createKeys', () {
    test('RSA keys (default)', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys();
      expect(result?.publicKey.asString(), 'test_public_key');
      expect(result?.algorithm, 'RSA');
      expect(result?.keySize, 2048);
    });

    test('EC keys', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys(
        androidConfig: AndroidConfig(
          useDeviceCredentials: false,
          signatureType: AndroidSignatureType.ECDSA,
        ),
      );
      expect(result?.algorithm, 'EC');
      expect(result?.keySize, 256);
    });

    test('Error handling', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setShouldThrowError(true);
      BiometricSignaturePlatform.instance = fakePlatform;

      expect(() => biometricSignature.createKeys(), throwsException);
    });
  });

  group('createSignature', () {
    test('Success with default options', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createSignature(
        SignatureOptions(
          payload: 'test',
          androidOptions: AndroidSignatureOptions(),
        ),
      );
      expect(result?.signature.asString(), 'test_signature');
      expect(result?.publicKey.asString(), 'test_public_key');
    });

    test('Error handling', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setShouldThrowError(true);
      BiometricSignaturePlatform.instance = fakePlatform;

      expect(
        () => biometricSignature.createSignature(
          SignatureOptions(payload: 'test'),
        ),
        throwsException,
      );
    });
  });

  test('deleteKeys', () async {
    BiometricSignature biometricSignature = BiometricSignature();
    MockBiometricSignaturePlatform fakePlatform =
        MockBiometricSignaturePlatform();
    BiometricSignaturePlatform.instance = fakePlatform;

    expect(await biometricSignature.deleteKeys(), true);
  });

  test('biometricKeyExists', () async {
    BiometricSignature biometricSignature = BiometricSignature();
    MockBiometricSignaturePlatform fakePlatform =
        MockBiometricSignaturePlatform();
    BiometricSignaturePlatform.instance = fakePlatform;

    expect(await biometricSignature.biometricKeyExists(), true);
  });

  group('decrypt', () {
    test('Success', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.decrypt(
        DecryptionOptions(payload: 'encrypted_payload'),
      );
      expect(result?.decryptedData, 'decrypted_encrypted_payload');
    });

    test('Error handling', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setShouldThrowError(true);
      BiometricSignaturePlatform.instance = fakePlatform;

      expect(
        () => biometricSignature.decrypt(
          DecryptionOptions(payload: 'encrypted_payload'),
        ),
        throwsException,
      );
    });
  });
}
