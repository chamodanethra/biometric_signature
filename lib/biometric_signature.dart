
import 'biometric_signature_platform_interface.dart';

class BiometricSignature {
  Future<String?> getPlatformVersion() {
    return BiometricSignaturePlatform.instance.getPlatformVersion();
  }
}
