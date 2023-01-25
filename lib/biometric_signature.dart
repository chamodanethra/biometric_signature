import 'biometric_signature_platform_interface.dart';

class BiometricSignature {

  Future<Map<String?, String?>?> createKeys() async {
    final Map<String?, String?>? response = await BiometricSignaturePlatform.instance.createKeys();
    return response;
  }

  Future<Map<String?, String?>?> createSignature({Map<String, String>? options}) async {
    final Map<String?, String?>? response = await BiometricSignaturePlatform.instance.createSignature(options: options);
    return response;
  }

  Future<Map<String?, String?>?> deleteKeys() async {
    final Map<String?, String?>? response = await BiometricSignaturePlatform.instance.deleteKeys();
    return response;
  }

  Future<Map<String?, String?>?> biometricAuthAvailable() async {
    final Map<String?, String?>? response = await BiometricSignaturePlatform.instance.biometricAuthAvailable();
    return response;
  }

  Future<Map<String?, String?>?> biometricKeysExist() async {
    final Map<String?, String?>? response = await BiometricSignaturePlatform.instance.biometricAuthAvailable();
    return response;
  }
}
