import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:biometric_signature/biometric_signature_method_channel.dart';

void main() {
  MethodChannelBiometricSignature platform = MethodChannelBiometricSignature();
  const MethodChannel channel = MethodChannel('biometric_signature');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await platform.getPlatformVersion(), '42');
  });
}
