import 'biometric_signature_platform_interface.dart';

class BiometricSignature {

  Future<String?> createKeys() async {
    final String? response = await BiometricSignaturePlatform.instance.createKeys();
    return response;
  }

  Future<String?> createSignature({Map<String, String>? options}) async {
    final String? response = await BiometricSignaturePlatform.instance.createSignature(options: options);
    return response;
  }

  Future<bool?> deleteKeys() async {
    final bool? response = await BiometricSignaturePlatform.instance.deleteKeys();
    return response;
  }

  Future<String?> biometricAuthAvailable() async {
    final String? response = await BiometricSignaturePlatform.instance.biometricAuthAvailable();
    return response;
  }

  Future<bool?> biometricKeyExists() async {
    final bool? response = await BiometricSignaturePlatform.instance.biometricKeyExists();
    return response;
  }
}
