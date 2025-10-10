import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:document_signer_example/models/document.dart';
import 'package:document_signer_example/models/signature_info.dart';
import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/signature_options.dart';
import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

class SignatureService {
  final BiometricSignature _biometric = BiometricSignature();
  static const String _publicKeyKey = 'document_signer_public_key';
  static const String _signerNameKey = 'document_signer_name';

  /// Initialize biometric keys
  Future<String> initializeKeys() async {
    try {
      final publicKey = await _biometric.createKeys(
        androidConfig: AndroidConfig(
          useDeviceCredentials: false,
          signatureType: AndroidSignatureType.RSA,
        ),
        iosConfig: IosConfig(
          useDeviceCredentials: false,
          signatureType: IOSSignatureType.RSA,
        ),
      );

      if (publicKey != null) {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString(_publicKeyKey, publicKey);
        return publicKey;
      }
      throw Exception('Failed to generate keys');
    } catch (e) {
      throw Exception('Key initialization failed: $e');
    }
  }

  /// Check if keys exist
  Future<bool> hasKeys() async {
    try {
      final exists = await _biometric.biometricKeyExists(checkValidity: true);
      return exists ?? false;
    } catch (e) {
      return false;
    }
  }

  /// Get stored public key
  Future<String?> getPublicKey() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_publicKeyKey);
  }

  /// Set signer name
  Future<void> setSignerName(String name) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_signerNameKey, name);
  }

  /// Get signer name
  Future<String> getSignerName() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_signerNameKey) ?? 'Unknown Signer';
  }

  /// Calculate document hash
  String calculateDocumentHash(String content) {
    final bytes = utf8.encode(content);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  /// Sign a document
  Future<SignatureInfo> signDocument(Document document) async {
    try {
      // Get biometric type
      final biometricType = await _biometric.biometricAuthAvailable();
      if (biometricType == null || biometricType.contains('none,')) {
        throw Exception('Biometric authentication not available');
      }

      // Calculate hash
      final documentHash = calculateDocumentHash(document.content);

      // Verify hash matches stored hash
      if (documentHash != document.contentHash) {
        throw Exception('Document has been modified since creation');
      }

      // Create signing payload
      final payload = jsonEncode({
        'documentId': document.id,
        'documentHash': documentHash,
        'timestamp': DateTime.now().toIso8601String(),
      });

      // Sign with biometric
      final signatureValue = await _biometric.createSignature(
        SignatureOptions(
          payload: payload,
          promptTitle: 'Sign "${document.title}"',
          androidOptions: const AndroidSignatureOptions(
            cancelButtonText: 'Cancel',
            allowDeviceCredentials: false,
          ),
          iosOptions: const IosSignatureOptions(
            shouldMigrate: false,
          ),
        ),
      );

      if (signatureValue == null) {
        throw Exception('Failed to create signature');
      }

      // Get signer info
      final publicKey = await getPublicKey();
      final signerName = await getSignerName();

      if (publicKey == null) {
        throw Exception('Public key not found');
      }

      return SignatureInfo(
        signatureValue: signatureValue,
        timestamp: DateTime.now(),
        signerPublicKey: publicKey,
        documentHash: documentHash,
        biometricType: biometricType,
        signerName: signerName,
      );
    } on PlatformException catch (e) {
      if (e.code == 'AUTH_FAILED') {
        throw Exception('Authentication failed: ${e.message}');
      } else if (e.code == 'CANCELLED') {
        throw Exception('Signing cancelled by user');
      }
      throw Exception('Signing failed: ${e.message}');
    }
  }

  /// Verify document signature (local verification)
  Future<bool> verifySignature(Document document) async {
    if (!document.isSigned) {
      return false;
    }

    final signature = document.signature!;

    // Recalculate document hash
    final currentHash = calculateDocumentHash(document.content);

    // Check if document has been modified
    if (currentHash != signature.documentHash) {
      return false;
    }

    // In a real app, you would verify the cryptographic signature here
    // using the public key. This requires platform-specific crypto libraries.
    // For this demo, we just verify the hash matches.

    return currentHash == document.contentHash;
  }

  /// Check biometric availability
  Future<bool> isBiometricAvailable() async {
    try {
      final result = await _biometric.biometricAuthAvailable();
      return result != null && !result.contains('none,');
    } catch (e) {
      return false;
    }
  }

  /// Delete keys
  Future<bool> deleteKeys() async {
    try {
      final result = await _biometric.deleteKeys();
      if (result == true) {
        final prefs = await SharedPreferences.getInstance();
        await prefs.remove(_publicKeyKey);
      }
      return result ?? false;
    } catch (e) {
      return false;
    }
  }
}
