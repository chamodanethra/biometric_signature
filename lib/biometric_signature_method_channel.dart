import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'biometric_signature_platform_interface.dart';

/// An implementation of [BiometricSignaturePlatform] that uses method channels.
class MethodChannelBiometricSignature extends BiometricSignaturePlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('biometric_signature');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
