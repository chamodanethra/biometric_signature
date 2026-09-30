import 'dart:typed_data';

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

  // Key attestation: aliases created with a challenge, and the chain the mock
  // keystore reports for them.
  final Set<String> _attestedAliases = {};
  final List<Uint8List> attestationChain = [
    Uint8List.fromList([0x30, 0x82, 0x01, 0x01]),
    Uint8List.fromList([0x30, 0x82, 0x02, 0x02]),
  ];
  CreateKeysConfig? lastCreateKeysConfig;

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
      attestationCertificateChain:
          _attestedAliases.contains(effectiveAlias) ? attestationChain : null,
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

    lastCreateKeysConfig = config;
    final effectiveAlias = keyAlias ?? 'biometric_key';
    final failIfExists = config?.failIfExists ?? false;

    if (failIfExists && _createdAliases.contains(effectiveAlias)) {
      return KeyCreationResult(
        code: BiometricError.keyAlreadyExists,
        error: 'Key with alias "$effectiveAlias" already exists',
      );
    }

    _createdAliases.add(effectiveAlias);
    final attested = config?.attestationChallenge != null;
    if (attested) {
      _attestedAliases.add(effectiveAlias);
    } else {
      _attestedAliases.remove(effectiveAlias);
    }

    final isEc =
        (config?.signatureType ?? _signatureType) == SignatureType.ecdsa;
    return KeyCreationResult(
      publicKey: 'test_public_key_$effectiveAlias',
      code: BiometricError.success,
      algorithm: isEc ? 'EC' : 'RSA',
      keySize: isEc ? 256 : 2048,
      attestationCertificateChain: attested ? attestationChain : null,
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
  Future<SignatureResult> createSignatureFromBytes(
    Uint8List payload,
    String? keyAlias,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) async {
    if (_shouldThrowError) throw Exception('Signing failed');

    final effectiveAlias = keyAlias ?? 'biometric_key';
    return SignatureResult(
      signature: 'test_signature_bytes_$effectiveAlias',
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
    _attestedAliases.remove(keyAlias ?? 'biometric_key');
    return Future.value(true);
  }

  @override
  Future<bool> deleteAllKeys() {
    deleteAllKeysCalled = true;
    _createdAliases.clear();
    _attestedAliases.clear();
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
  // The Pigeon wire-format tests below talk to a mock binary messenger.
  TestWidgetsFlutterBinding.ensureInitialized();

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

  group('createSignatureFromBytes', () {
    test('Success with default options', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createSignatureFromBytes(
        payload: Uint8List.fromList([1, 2, 3, 4]),
      );
      expect(result.signature, 'test_signature_bytes_biometric_key');
      expect(result.publicKey, 'test_public_key_biometric_key');
      expect(result.code, BiometricError.success);
    });

    test('with custom prompt message', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createSignatureFromBytes(
        payload: Uint8List.fromList([5, 6, 7]),
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
        () => biometricSignature.createSignatureFromBytes(
            payload: Uint8List.fromList([1])),
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

  group('key attestation', () {
    late BiometricSignature biometricSignature;
    late MockBiometricSignaturePlatform fakePlatform;
    final challenge = Uint8List.fromList(List<int>.generate(32, (i) => i));

    setUp(() {
      biometricSignature = BiometricSignature();
      fakePlatform = MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;
    });

    test('createKeys passes the challenge through and returns the chain',
        () async {
      final result = await biometricSignature.createKeys(
        config: CreateKeysConfig(
          signatureType: SignatureType.ecdsa,
          attestationChallenge: challenge,
        ),
      );

      expect(
        fakePlatform.lastCreateKeysConfig?.attestationChallenge,
        challenge,
      );
      expect(result.code, BiometricError.success);
      expect(result.attestationCertificateChain, fakePlatform.attestationChain);
    });

    test('createKeys without a challenge returns no chain', () async {
      final result = await biometricSignature.createKeys();

      expect(fakePlatform.lastCreateKeysConfig?.attestationChallenge, isNull);
      expect(result.attestationCertificateChain, isNull);
    });

    test('getKeyInfo reports the chain only for attested keys', () async {
      await biometricSignature.createKeys(
        keyAlias: 'attested',
        config: CreateKeysConfig(attestationChallenge: challenge),
      );
      await biometricSignature.createKeys(keyAlias: 'plain');

      final attested = await biometricSignature.getKeyInfo(
        keyAlias: 'attested',
      );
      final plain = await biometricSignature.getKeyInfo(keyAlias: 'plain');

      expect(
        attested.attestationCertificateChain,
        fakePlatform.attestationChain,
      );
      expect(plain.attestationCertificateChain, isNull);
    });
  });

  // Exercises the real Pigeon codec and channel plumbing (not the mock
  // platform), so a field missing from the generated classes or encoded at
  // the wrong position fails here.
  group('Pigeon wire format', () {
    const codec = BiometricSignatureApi.pigeonChannelCodec;
    const channelPrefix =
        'dev.flutter.pigeon.biometric_signature.BiometricSignatureApi';
    final challenge = Uint8List.fromList(
      List<int>.generate(128, (i) => 255 - i),
    );
    final chain = [
      Uint8List.fromList([0x30, 0x82, 0x01, 0x0a]),
      Uint8List.fromList([0x30, 0x82, 0x02, 0x0b]),
      Uint8List.fromList([0x30, 0x82, 0x03, 0x0c]),
    ];

    TestDefaultBinaryMessenger messenger() =>
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

    setUp(() {
      // Earlier tests leave a mock platform installed.
      BiometricSignaturePlatform.instance = initialPlatform;
    });

    tearDown(() {
      messenger().setMockMessageHandler('$channelPrefix.createKeys', null);
      messenger().setMockMessageHandler('$channelPrefix.getKeyInfo', null);
    });

    test('createKeys sends attestationChallenge and decodes the chain',
        () async {
      CreateKeysConfig? sentConfig;
      messenger().setMockMessageHandler('$channelPrefix.createKeys', (
        ByteData? message,
      ) async {
        final args = codec.decodeMessage(message)! as List<Object?>;
        sentConfig = args[1] as CreateKeysConfig?;
        return codec.encodeMessage(<Object?>[
          KeyCreationResult(
            code: BiometricError.success,
            attestationCertificateChain: chain,
          ),
        ]);
      });

      final result = await BiometricSignature().createKeys(
        config: CreateKeysConfig(attestationChallenge: challenge),
      );

      expect(sentConfig?.attestationChallenge, challenge);
      expect(result.code, BiometricError.success);
      expect(result.attestationCertificateChain, chain);
    });

    test('createKeys sends every attestationMode', () async {
      final sentModes = <AttestationMode?>[];
      messenger().setMockMessageHandler('$channelPrefix.createKeys', (
        ByteData? message,
      ) async {
        final args = codec.decodeMessage(message)! as List<Object?>;
        sentModes.add((args[1] as CreateKeysConfig?)?.attestationMode);
        return codec.encodeMessage(<Object?>[
          KeyCreationResult(code: BiometricError.success),
        ]);
      });

      for (final mode in AttestationMode.values) {
        await BiometricSignature().createKeys(
          config: CreateKeysConfig(
            attestationChallenge: challenge,
            attestationMode: mode,
          ),
        );
      }
      await BiometricSignature().createKeys(
        config: CreateKeysConfig(attestationChallenge: challenge),
      );

      expect(sentModes, [...AttestationMode.values, null]);
    });

    test('createKeys decodes the attestation fallback reason', () async {
      messenger().setMockMessageHandler('$channelPrefix.createKeys', (
        ByteData? message,
      ) async {
        return codec.encodeMessage(<Object?>[
          KeyCreationResult(
            code: BiometricError.success,
            publicKey: 'unattested',
            attestationErrorCode: BiometricError.notAvailable,
            attestationError: 'Key attestation is temporarily unavailable',
          ),
        ]);
      });

      final result = await BiometricSignature().createKeys(
        config: CreateKeysConfig(
          attestationChallenge: challenge,
          attestationMode: AttestationMode.preferred,
        ),
      );

      expect(result.code, BiometricError.success);
      expect(result.publicKey, 'unattested');
      expect(result.attestationCertificateChain, isNull);
      expect(result.attestationErrorCode, BiometricError.notAvailable);
      expect(
        result.attestationError,
        'Key attestation is temporarily unavailable',
      );
    });

    test('getKeyInfo decodes the chain', () async {
      messenger().setMockMessageHandler('$channelPrefix.getKeyInfo', (
        ByteData? message,
      ) async {
        return codec.encodeMessage(<Object?>[
          KeyInfo(exists: true, attestationCertificateChain: chain),
        ]);
      });

      final info = await BiometricSignature().getKeyInfo();

      expect(info.exists, isTrue);
      expect(info.attestationCertificateChain, chain);
    });
  });
}
