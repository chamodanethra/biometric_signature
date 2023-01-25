import 'package:flutter_test/flutter_test.dart';
import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/biometric_signature_platform_interface.dart';
import 'package:biometric_signature/biometric_signature_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockBiometricSignaturePlatform
    with MockPlatformInterfaceMixin
    implements BiometricSignaturePlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final BiometricSignaturePlatform initialPlatform = BiometricSignaturePlatform.instance;

  test('$MethodChannelBiometricSignature is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelBiometricSignature>());
  });

  test('getPlatformVersion', () async {
    BiometricSignature biometricSignaturePlugin = BiometricSignature();
    MockBiometricSignaturePlatform fakePlatform = MockBiometricSignaturePlatform();
    BiometricSignaturePlatform.instance = fakePlatform;

    expect(await biometricSignaturePlugin.getPlatformVersion(), '42');
  });
}
