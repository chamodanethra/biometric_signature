import 'package:biometric_signature/biometric_signature.dart'
    hide BiometricAvailability;
import 'package:biometric_signature/biometric_signature.dart' as plugin
    show BiometricAvailability;
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

class BiometricService {
  final BiometricSignature _biometric = BiometricSignature();
  static const String _publicKeyKey = 'biometric_public_key';

  /// Check if biometric authentication is available
  Future<BiometricAvailability> checkAvailability() async {
    try {
      final result = await _biometric.biometricAuthAvailable();
      print('result: $result');
      if (!(result.canAuthenticate ?? false)) {
        return BiometricAvailability(
          isAvailable: false,
          biometricType: 'none',
          errorMessage: result.reason,
        );
      }
      final biometricTypes = (result.availableBiometrics ?? [])
          .map((b) => b?.name ?? '')
          .where((s) => s.isNotEmpty)
          .join(',');
      return BiometricAvailability(
        isAvailable: true,
        biometricType: biometricTypes.isNotEmpty ? biometricTypes : 'biometric',
      );
    } catch (e) {
      return BiometricAvailability(
        isAvailable: false,
        biometricType: 'none',
        errorMessage: e.toString(),
      );
    }
  }

  /// Initialize biometric keys (first-time setup)
  Future<String> initializeKeys() async {
    try {
      final keyResult = await _biometric.createKeys(
        keyFormat: KeyFormat.base64,
        config: CreateKeysConfig(
          useDeviceCredentials: false,
          signatureType: SignatureType.rsa,
          enforceBiometric: true,
        ),
      );

      final publicKey = keyResult.publicKey;
      if (publicKey != null) {
        // Store public key for future reference
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString(_publicKeyKey, publicKey);
        return publicKey;
      }
      throw Exception('Failed to generate keys: ${keyResult.error}');
    } on PlatformException catch (e) {
      throw Exception('Biometric key creation failed: ${e.message}');
    }
  }

  /// Check if keys exist
  Future<bool> hasKeys() async {
    try {
      final exists = await _biometric.biometricKeyExists(checkValidity: true);
      return exists;
    } catch (e) {
      return false;
    }
  }

  /// Get stored public key
  Future<String?> getPublicKey() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_publicKeyKey);
  }

  /// Sign data with biometric authentication
  Future<String> signData(String payload, String promptMessage) async {
    try {
      final signatureResult = await _biometric.createSignature(
        payload: payload,
        promptMessage: promptMessage,
        signatureFormat: SignatureFormat.base64,
        keyFormat: KeyFormat.base64,
        config: CreateSignatureConfig(
          cancelButtonText: 'Cancel',
          allowDeviceCredentials: false,
        ),
      );

      final signature = signatureResult.signature;
      if (signature != null) {
        return signature;
      }
      throw Exception('Failed to create signature: ${signatureResult.error}');
    } on PlatformException catch (e) {
      if (e.code == 'AUTH_FAILED') {
        throw Exception('Authentication failed: ${e.message}');
      } else if (e.code == 'CANCELLED') {
        throw Exception('Authentication cancelled');
      }
      throw Exception('Signature creation failed: ${e.message}');
    }
  }

  /// Delete biometric keys
  Future<bool> deleteKeys() async {
    try {
      final result = await _biometric.deleteKeys();
      if (result == true) {
        final prefs = await SharedPreferences.getInstance();
        await prefs.remove(_publicKeyKey);
      }
      return result;
    } catch (e) {
      return false;
    }
  }
}

class BiometricAvailability {
  final bool isAvailable;
  final String biometricType;
  final String? errorMessage;

  BiometricAvailability({
    required this.isAvailable,
    required this.biometricType,
    this.errorMessage,
  });

  String get displayName {
    if (!isAvailable) return 'Not Available';
    if (biometricType.toLowerCase().contains('face')) return 'Face Recognition';
    if (biometricType.toLowerCase().contains('fingerprint') ||
        biometricType.toLowerCase().contains('touch')) {
      return 'Fingerprint';
    }
    return 'Biometric';
  }
}
