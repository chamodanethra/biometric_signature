import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';

import 'biometric_signature_platform_interface.dart';
import 'signature_options.dart';

/// High-level API for interacting with the Biometric Signature plugin.
class BiometricSignature {
  /// Creates a key pair on the device and stores the private key in the
  /// StrongBox or KeyStore/Secure Enclave.
  ///
  /// params: An optional AndroidConfig object containing the bool
  /// useDeviceCredentials and AndroidSignatureType signatureType (RSA or ECDSA),
  /// and an optional IosConfig object containing the bool useDeviceCredentials
  /// and IOSSignatureType signatureType (RSA or ECDSA)
  /// Returns: The public key component encoded as a [String].
  Future<String?> createKeys({
    AndroidConfig? androidConfig,
    IosConfig? iosConfig,
  }) async {
    final String? response =
        await BiometricSignaturePlatform.instance.createKeys(
      androidConfig ?? AndroidConfig(useDeviceCredentials: false),
      iosConfig ?? IosConfig(useDeviceCredentials: false),
    );
    return response;
  }

  /// Creates a digital signature using biometric authentication.
  ///
  /// params: A [SignatureOptions] instance containing the payload to sign, an
  /// optional prompt message, and platform-specific configuration.
  /// Returns: Either the created signature as a base64 encoded string or an
  /// error.
  Future<String?> createSignature(SignatureOptions options) async {
    final String? response =
        await BiometricSignaturePlatform.instance.createSignature(options);
    return response;
  }

  /// Legacy helper maintained for migration from the map-based API.
  @Deprecated('Use createSignature(SignatureOptions options) instead.')
  Future<String?> createSignatureFromLegacyOptions(
    Map<String, String> options,
  ) async {
    return createSignature(SignatureOptions.fromLegacyMap(options));
  }

  /// Deletes the biometric key if it exists.
  ///
  /// Returns: A [bool] indicating whether the deletion was successful
  Future<bool?> deleteKeys() async {
    final bool? response =
        await BiometricSignaturePlatform.instance.deleteKeys();
    return response;
  }

  /// Determines whether biometric authentication is available on the device.
  ///
  /// Returns: A [String] indicating biometric type if available, otherwise returns none, and the reason
  Future<String?> biometricAuthAvailable() async {
    final String? response =
        await BiometricSignaturePlatform.instance.biometricAuthAvailable();
    return response;
  }

  /// Checks whether the biometric key exists in the StrongBox or KeyStore/Secure Enclave.
  ///
  /// params: An optional bool named [checkValidity], to check if the key is valid
  /// Returns: A [bool] indicating whether the biometric key exists
  Future<bool?> biometricKeyExists({bool checkValidity = false}) async {
    final bool? response = await BiometricSignaturePlatform.instance
        .biometricKeyExists(checkValidity);
    return response;
  }
}
