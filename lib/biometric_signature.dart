import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';

import 'biometric_signature_platform_interface.dart';
import 'key_material.dart';
import 'signature_options.dart';

export 'key_material.dart';

/// High-level API for interacting with the Biometric Signature plugin.
class BiometricSignature {
  /// Creates a key pair on the device and stores the private key in the
  /// StrongBox or KeyStore/Secure Enclave.
  ///
  /// Returns the public key using the requested [keyFormat].
  Future<KeyCreationResult?> createKeys({
    AndroidConfig? androidConfig,
    IosConfig? iosConfig,
    KeyFormat keyFormat = KeyFormat.base64,
    bool setInvalidatedByBiometricEnrollment = true,
    bool enforceBiometric = false,
  }) async {
    final response = await BiometricSignaturePlatform.instance.createKeys(
      androidConfig ??
          AndroidConfig(
            useDeviceCredentials: false,
            setInvalidatedByBiometricEnrollment: true,
          ),
      iosConfig ??
          IosConfig(useDeviceCredentials: false, biometryCurrentSet: true),
      keyFormat: keyFormat,
      enforceBiometric: enforceBiometric,
    );
    return response == null ? null : KeyCreationResult.fromChannel(response);
  }

  /// Creates a digital signature using biometric authentication.
  ///
  /// The output respects the [SignatureOptions.keyFormat] that defaults to
  /// [KeyFormat.base64] for backward compatibility.
  Future<SignatureResult?> createSignature(SignatureOptions options) async {
    final response = await BiometricSignaturePlatform.instance.createSignature(
      options,
    );
    return response == null ? null : SignatureResult.fromChannel(response);
  }

  /// Deletes the biometric key if it exists.
  ///
  /// Returns: A [bool] indicating whether the deletion was successful or an error.
  Future<bool?> deleteKeys() async {
    final bool? response = await BiometricSignaturePlatform.instance
        .deleteKeys();
    return response;
  }

  /// Determines whether biometric authentication is available on the device.
  ///
  /// Returns: A [String] indicating biometric type if available, otherwise returns none, and the reason.
  Future<String?> biometricAuthAvailable() async {
    final String? response = await BiometricSignaturePlatform.instance
        .biometricAuthAvailable();
    return response;
  }

  /// Checks whether the biometric key exists in the StrongBox or KeyStore/Secure Enclave.
  ///
  /// params: An optional bool named [checkValidity], to check if the key is valid.
  /// Returns: A [bool] indicating whether the biometric key exists.
  Future<bool?> biometricKeyExists({bool checkValidity = false}) async {
    final bool? response = await BiometricSignaturePlatform.instance
        .biometricKeyExists(checkValidity);
    return response;
  }
}
