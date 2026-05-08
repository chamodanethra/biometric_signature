import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/biometric_signature_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockBiometricSignaturePlatform
    with MockPlatformInterfaceMixin
    implements BiometricSignaturePlatform {
  BiometricAvailability _authAvailableResult = BiometricAvailability(
    canAuthenticate: true,
    hasEnrolledBiometrics: true,
    availableBiometrics: [BiometricType.fingerprint],
    reason: null,
  );
  bool _shouldThrowError = false;
  SignatureType _signatureType = SignatureType.rsa;

  // Track which aliases have been "created" to test failIfExists
  final Set<String> _createdAliases = {};
  // Track deletion calls
  final List<String?> deletedAliases = [];
  bool deleteAllKeysCalled = false;

  void setAuthAvailableResult(BiometricAvailability result) {
    _authAvailableResult = result;
  }

  void setShouldThrowError(bool value) {
    _shouldThrowError = value;
  }

  void setSignatureType(SignatureType type) {
    _signatureType = type;
  }

  void addCreatedAlias(String alias) {
    _createdAliases.add(alias);
  }

  @override
  Future<BiometricAvailability> biometricAuthAvailable() async {
    if (_shouldThrowError) throw Exception('Auth check failed');
    return _authAvailableResult;
  }

  @override
  Future<KeyInfo> getKeyInfo(
    String? keyAlias,
    bool checkValidity,
    KeyFormat keyFormat,
  ) async {
    final effectiveAlias = keyAlias ?? 'biometric_key';
    if (!_createdAliases.contains(effectiveAlias)) {
      return KeyInfo(exists: false);
    }
    return KeyInfo(
      exists: true,
      isValid: true,
      algorithm: 'RSA',
      keySize: 2048,
      isHybridMode: false,
      publicKey: 'test_public_key_$effectiveAlias',
    );
  }

  @override
  Future<KeyCreationResult> createKeys(
    String? keyAlias,
    CreateKeysConfig? config,
    KeyFormat keyFormat,
    String? promptMessage,
  ) async {
    if (_shouldThrowError) throw Exception('Key creation failed');

    final effectiveAlias = keyAlias ?? 'biometric_key';
    final failIfExists = config?.failIfExists ?? false;

    if (failIfExists && _createdAliases.contains(effectiveAlias)) {
      return KeyCreationResult(
        code: BiometricError.keyAlreadyExists,
        error: 'Key with alias "$effectiveAlias" already exists',
      );
    }

    _createdAliases.add(effectiveAlias);

    final isEc =
        (config?.signatureType ?? _signatureType) == SignatureType.ecdsa;
    return KeyCreationResult(
      publicKey: 'test_public_key_$effectiveAlias',
      code: BiometricError.success,
      algorithm: isEc ? 'EC' : 'RSA',
      keySize: isEc ? 256 : 2048,
    );
  }

  @override
  Future<SignatureResult> createSignature(
    String payload,
    String? keyAlias,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) async {
    if (_shouldThrowError) throw Exception('Signing failed');

    final effectiveAlias = keyAlias ?? 'biometric_key';
    return SignatureResult(
      signature: 'test_signature_$effectiveAlias',
      publicKey: 'test_public_key_$effectiveAlias',
      code: BiometricError.success,
      algorithm: 'RSA',
      keySize: 2048,
    );
  }

  @override
  Future<bool> deleteKeys(String? keyAlias) {
    deletedAliases.add(keyAlias);
    _createdAliases.remove(keyAlias ?? 'biometric_key');
    return Future.value(true);
  }

  @override
  Future<bool> deleteAllKeys() {
    deleteAllKeysCalled = true;
    _createdAliases.clear();
    return Future.value(true);
  }

  @override
  Future<DecryptResult> decrypt(
    String payload,
    String? keyAlias,
    PayloadFormat payloadFormat,
    DecryptConfig? config,
    String? promptMessage,
  ) async {
    if (_shouldThrowError) throw Exception('Decryption failed');

    final effectiveAlias = keyAlias ?? 'biometric_key';
    return DecryptResult(
      decryptedData: 'decrypted_${effectiveAlias}_$payload',
      code: BiometricError.success,
    );
  }

  @override
  Future<SimplePromptResult> simplePrompt(
    String promptMessage,
    SimplePromptConfig? config,
  ) async {
    if (_shouldThrowError) throw Exception('Simple prompt failed');

    return SimplePromptResult(
      success: true,
      error: null,
      code: BiometricError.success,
    );
  }

  @override
  Future<bool> isDeviceLockSet() {
    // TODO: implement isDeviceLockSet
    throw UnimplementedError();
  }
}

void main() {
  final BiometricSignaturePlatform initialPlatform =
      BiometricSignaturePlatform.instance;

  test('\$BiometricSignaturePlatform is the default instance', () {
    expect(initialPlatform, isInstanceOf<BiometricSignaturePlatform>());
  });

  group('biometricAuthAvailable', () {
    test('returns availability info', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.biometricAuthAvailable();
      expect(result.canAuthenticate, true);
      expect(result.hasEnrolledBiometrics, true);
      expect(result.availableBiometrics, contains(BiometricType.fingerprint));
    });

    test('handles unavailable biometrics', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setAuthAvailableResult(
        BiometricAvailability(
          canAuthenticate: false,
          hasEnrolledBiometrics: false,
          availableBiometrics: [BiometricType.unavailable],
          reason: 'No biometric hardware',
        ),
      );
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.biometricAuthAvailable();
      expect(result.canAuthenticate, false);
      expect(result.reason, 'No biometric hardware');
    });
  });

  group('createKeys', () {
    test('RSA keys (default)', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys();
      expect(result.publicKey, 'test_public_key_biometric_key');
      expect(result.algorithm, 'RSA');
      expect(result.keySize, 2048);
      expect(result.code, BiometricError.success);
    });

    test('EC keys', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys(
        config: CreateKeysConfig(signatureType: SignatureType.ecdsa),
      );
      expect(result.algorithm, 'EC');
      expect(result.keySize, 256);
    });

    test('with config options', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys(
        config: CreateKeysConfig(
          enableDecryption: true,
          promptSubtitle: 'Test subtitle',
          enforceBiometric: true,
          setInvalidatedByBiometricEnrollment: true,
        ),
      );
      expect(result.code, BiometricError.success);
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
        payload: 'test_data',
      );
      expect(result.signature, 'test_signature_biometric_key');
      expect(result.publicKey, 'test_public_key_biometric_key');
      expect(result.code, BiometricError.success);
    });

    test('with custom prompt message', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createSignature(
        payload: 'test_data',
        promptMessage: 'Please authenticate',
        config: CreateSignatureConfig(allowDeviceCredentials: false),
      );
      expect(result.code, BiometricError.success);
    });

    test('Error handling', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setShouldThrowError(true);
      BiometricSignaturePlatform.instance = fakePlatform;

      expect(
        () => biometricSignature.createSignature(payload: 'test'),
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
    fakePlatform.addCreatedAlias('biometric_key');
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
        payload: 'encrypted_payload',
        payloadFormat: PayloadFormat.base64,
      );
      expect(result.decryptedData, 'decrypted_biometric_key_encrypted_payload');
      expect(result.code, BiometricError.success);
    });

    test('with config options', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.decrypt(
        payload: 'encrypted_payload',
        payloadFormat: PayloadFormat.base64,
        config: DecryptConfig(allowDeviceCredentials: false),
      );
      expect(result.code, BiometricError.success);
    });

    test('Error handling', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setShouldThrowError(true);
      BiometricSignaturePlatform.instance = fakePlatform;

      expect(
        () => biometricSignature.decrypt(
          payload: 'encrypted_payload',
          payloadFormat: PayloadFormat.base64,
        ),
        throwsException,
      );
    });
  });

  group('simplePrompt', () {
    test('Success', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.simplePrompt(
        promptMessage: 'Verify identity',
      );
      expect(result.success, true);
      expect(result.code, BiometricError.success);
    });

    test('with config options', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.simplePrompt(
        promptMessage: 'Verify identity',
        config: SimplePromptConfig(
          subtitle: 'Test subtitle',
          allowDeviceCredentials: true,
        ),
      );
      expect(result.success, true);
    });

    test('Error handling', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setShouldThrowError(true);
      BiometricSignaturePlatform.instance = fakePlatform;

      expect(
        () => biometricSignature.simplePrompt(promptMessage: 'Verify'),
        throwsException,
      );
    });
  });

  // ============================================================
  // Step 2: Named Key Aliases
  // ============================================================

  group('named key aliases', () {
    test('createKeys with custom alias', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys(
        keyAlias: 'payment_signing',
      );
      expect(result.publicKey, 'test_public_key_payment_signing');
      expect(result.code, BiometricError.success);
    });

    test('createKeys with null alias uses default', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys();
      expect(result.publicKey, 'test_public_key_biometric_key');
    });

    test('multiple independent aliases', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final authResult = await biometricSignature.createKeys(keyAlias: 'auth');
      final paymentResult = await biometricSignature.createKeys(
        keyAlias: 'payment',
      );

      expect(authResult.publicKey, 'test_public_key_auth');
      expect(paymentResult.publicKey, 'test_public_key_payment');
      expect(authResult.publicKey, isNot(paymentResult.publicKey));
    });

    test('createSignature with alias', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createSignature(
        payload: 'test_data',
        keyAlias: 'payment',
      );
      expect(result.signature, 'test_signature_payment');
      expect(result.publicKey, 'test_public_key_payment');
    });

    test('decrypt with alias', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.decrypt(
        payload: 'ciphertext',
        payloadFormat: PayloadFormat.base64,
        keyAlias: 'payment',
      );
      expect(result.decryptedData, 'decrypted_payment_ciphertext');
    });

    test('getKeyInfo with alias', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.addCreatedAlias('payment');
      BiometricSignaturePlatform.instance = fakePlatform;

      final info = await biometricSignature.getKeyInfo(keyAlias: 'payment');
      expect(info.exists, true);
      expect(info.publicKey, 'test_public_key_payment');
    });

    test('getKeyInfo with unknown alias returns exists=false', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final info = await biometricSignature.getKeyInfo(keyAlias: 'nonexistent');
      expect(info.exists, false);
    });

    test('biometricKeyExists with alias', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.addCreatedAlias('payment');
      BiometricSignaturePlatform.instance = fakePlatform;

      expect(
        await biometricSignature.biometricKeyExists(keyAlias: 'payment'),
        true,
      );
      expect(
        await biometricSignature.biometricKeyExists(keyAlias: 'nonexistent'),
        false,
      );
    });
  });

  // ============================================================
  // Step 3: Key Overwrite Protection & Safe Deletion
  // ============================================================

  group('key overwrite protection', () {
    test('failIfExists prevents overwriting existing key', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      // Create a key first
      final first = await biometricSignature.createKeys(keyAlias: 'payment');
      expect(first.code, BiometricError.success);

      // Try to create again with failIfExists
      final second = await biometricSignature.createKeys(
        keyAlias: 'payment',
        config: CreateKeysConfig(failIfExists: true),
      );
      expect(second.code, BiometricError.keyAlreadyExists);
      expect(second.error, contains('already exists'));
    });

    test('failIfExists allows creation when key does not exist', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys(
        keyAlias: 'new_key',
        config: CreateKeysConfig(failIfExists: true),
      );
      expect(result.code, BiometricError.success);
      expect(result.publicKey, 'test_public_key_new_key');
    });

    test('default failIfExists=false allows overwrite', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      await biometricSignature.createKeys(keyAlias: 'payment');
      final second = await biometricSignature.createKeys(keyAlias: 'payment');
      expect(second.code, BiometricError.success);
    });

    test('failIfExists on default alias', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      await biometricSignature.createKeys();
      final second = await biometricSignature.createKeys(
        config: CreateKeysConfig(failIfExists: true),
      );
      expect(second.code, BiometricError.keyAlreadyExists);
    });
  });

  group('safe deletion', () {
    test('deleteKeys with alias deletes only that alias', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      await biometricSignature.createKeys(keyAlias: 'auth');
      await biometricSignature.createKeys(keyAlias: 'payment');

      await biometricSignature.deleteKeys(keyAlias: 'auth');

      expect(fakePlatform.deletedAliases, ['auth']);

      // 'payment' should still exist
      final paymentInfo = await biometricSignature.getKeyInfo(
        keyAlias: 'payment',
      );
      expect(paymentInfo.exists, true);

      // 'auth' should be gone
      final authInfo = await biometricSignature.getKeyInfo(keyAlias: 'auth');
      expect(authInfo.exists, false);
    });

    test('deleteKeys with no alias deletes default', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      await biometricSignature.deleteKeys();
      expect(fakePlatform.deletedAliases, [null]);
    });

    test('deleteAllKeys clears everything', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      await biometricSignature.createKeys(keyAlias: 'auth');
      await biometricSignature.createKeys(keyAlias: 'payment');

      await biometricSignature.deleteAllKeys();
      expect(fakePlatform.deleteAllKeysCalled, true);

      // All keys should be gone
      final authInfo = await biometricSignature.getKeyInfo(keyAlias: 'auth');
      expect(authInfo.exists, false);
      final paymentInfo = await biometricSignature.getKeyInfo(
        keyAlias: 'payment',
      );
      expect(paymentInfo.exists, false);
    });

    test('deleting nonexistent key is idempotent', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.deleteKeys(
        keyAlias: 'nonexistent',
      );
      expect(result, true);
    });
  });
}
