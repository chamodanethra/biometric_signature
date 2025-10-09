import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/ios_config.dart';
import 'package:biometric_signature/signature_options.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('biometric signature test app')),
        body: const ExampleAppBody(),
      ),
    );
  }
}

class ExampleAppBody extends StatefulWidget {
  const ExampleAppBody({super.key});

  @override
  State<ExampleAppBody> createState() => _ExampleAppBodyState();
}

class _ExampleAppBodyState extends State<ExampleAppBody> {
  final _biometricSignature = BiometricSignature();

  bool useEc = true;
  KeyCreationResult? keyMaterial;
  SignatureResult? signatureResult;
  String? payload;

  Future<void> _createPublicKey() async {
    final result = await _biometricSignature.createKeys(
      androidConfig: AndroidConfig(
        useDeviceCredentials: true,
        signatureType: useEc
            ? AndroidSignatureType.ECDSA
            : AndroidSignatureType.RSA,
      ),
      iosConfig: IosConfig(
        useDeviceCredentials: false,
        signatureType: useEc ? IOSSignatureType.ECDSA : IOSSignatureType.RSA,
      ),
    );
    setState(() => keyMaterial = result);
    if (result != null) {
      final display =
          result.publicKey.asString() ?? result.publicKey.toBase64();
      debugPrint('publicKey (${result.publicKey.format.wireValue}): $display');
    }
    debugPrint(await _biometricSignature.biometricAuthAvailable());
  }

  void _toggleEc(bool newValue) {
    setState(() => useEc = newValue);
    _biometricSignature.deleteKeys().then((success) {
      debugPrint('deleteKeys success: $success');
      if (success ?? false) {
        setState(() {
          keyMaterial = null;
          signatureResult = null;
        });
      }
    });
  }

  void _payloadChanged(String value) {
    if (value == payload) {
      return;
    }
    setState(() {
      payload = value;
      signatureResult = null;
    });
  }

  Future<void> _createSignature() async {
    if (payload == null || payload!.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('please enter payload')));
      return;
    }
    final result = await _biometricSignature.createSignature(
      SignatureOptions(
        payload: payload!,
        promptMessage: 'Sign Payload',
        androidOptions: const AndroidSignatureOptions(
          allowDeviceCredentials: true,
        ),
        iosOptions: const IosSignatureOptions(shouldMigrate: false),
      ),
    );
    setState(() => signatureResult = result);
    if (result != null) {
      final display =
          result.signature.asString() ?? result.signature.toBase64();
      debugPrint('signature (${result.signature.format.wireValue}): $display');
    }
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Text('use EC'),
                Switch(value: useEc, onChanged: _toggleEc),
              ],
            ),
            TextButton(
              onPressed: _createPublicKey,
              child: Text('create ${useEc ? 'EC' : 'RSA'} keys'),
            ),
            if (keyMaterial != null)
              Text(
                'publicKey (${keyMaterial!.publicKey.format.wireValue}):\n'
                '${keyMaterial!.publicKey.asString() ?? keyMaterial!.publicKey.toBase64()}',
              ),
            const Spacer(),
            if (signatureResult != null)
              Text(
                'signature (${signatureResult!.signature.format.wireValue}):\n'
                '${signatureResult!.signature.asString() ?? signatureResult!.signature.toBase64()}',
              ),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    decoration: const InputDecoration(labelText: 'payload'),
                    onChanged: _payloadChanged,
                  ),
                ),
                TextButton(
                  onPressed: _createSignature,
                  child: const Text('sign'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
