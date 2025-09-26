import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';

import 'biometric_signature_platform_interface.dart';
import 'signature_options.dart';

class BiometricSignature {
  /// Creates a key pair on the device, stores Private Key in keychain/keystore
  ///
  /// params: An optional AndroidConfig object containing the bool useDeviceCredentials and AndroidSignatureType signatureType (RSA or ECDSA), and an optional IosConfig object containing the bool useDeviceCredentials and IOSSignatureType signatureType (RSA or ECDSA)
  /// Returns: The Public Key component as a String
  Future<String?> createKeys({
    AndroidConfig? androidConfig,
    IosConfig? iosConfig,
  }) async {
    final String? response = await BiometricSignaturePlatform.instance
        .createKeys(
          androidConfig ?? AndroidConfig(useDeviceCredentials: false),
          iosConfig ?? IosConfig(useDeviceCredentials: false),
        );
    return response;
  }

  /// Creates a digital signature using biometric authentication.
  ///
  /// params: A [SignatureOptions] instance containing the payload to sign, an
  /// optional prompt message, and platform-specific configuration.
  /// - Returns: Either the created signature as a base64 encoded string or an
  /// error.
  Future<String?> createSignature(SignatureOptions options) async {
    final String? response = await BiometricSignaturePlatform.instance
        .createSignature(options);
    return response;
  }

  /// Legacy helper maintained for migration from the map-based API.
  @Deprecated('Use createSignature(SignatureOptions options) instead.')
  Future<String?> createSignatureFromLegacyOptions(
    Map<String, String> options,
  ) async {
    return createSignature(SignatureOptions.fromLegacyMap(options));
  }

  /// Delete the biometric key if exists
  ///
  /// - Returns: A boolean indicating whether the deletion was successful
  Future<bool?> deleteKeys() async {
    final bool? response = await BiometricSignaturePlatform.instance
        .deleteKeys();
    return response;
  }

  /// Determine if the biometric authentication is available
  ///
  /// - Returns: A String indicating biometric type if available, otherwise returns none, and the reason
  Future<String?> biometricAuthAvailable() async {
    final String? response = await BiometricSignaturePlatform.instance
        .biometricAuthAvailable();
    return response;
  }

  /// Check if the biometric key exists in the keychain/keystore
  ///
  /// params: An optional bool named checkValidity, to check if the key is valid
  /// - Returns: A boolean indicating whether the biometric key exists
  Future<bool?> biometricKeyExists({bool checkValidity = false}) async {
    final bool? response = await BiometricSignaturePlatform.instance
        .biometricKeyExists(checkValidity);
    return response;
  }
}
