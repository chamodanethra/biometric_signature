import 'dart:io';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:encrypt/encrypt.dart' as enc;
import 'package:flutter/material.dart';
import 'package:pointycastle/asymmetric/api.dart';

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

  bool useEc = false;
  bool enableAndroidDecryption = false;
  KeyCreationResult? keyMaterial;
  SignatureResult? signatureResult;
  String? decryptResult;
  String? payload;

  Future<void> _createPublicKey() async {
    final result = await _biometricSignature.createKeys(
      androidConfig: AndroidConfig(
        useDeviceCredentials: false,
        signatureType: useEc
            ? AndroidSignatureType.ECDSA
            : AndroidSignatureType.RSA,
        setInvalidatedByBiometricEnrollment: true,
        enableDecryption: enableAndroidDecryption,
      ),
      iosConfig: IosConfig(
        useDeviceCredentials: false,
        signatureType: useEc ? IOSSignatureType.ECDSA : IOSSignatureType.RSA,
        biometryCurrentSet: true,
      ),
      enforceBiometric: true,
    );
    setState(() => keyMaterial = result);
    if (result != null) {
      final display =
          result.publicKey.asString() ?? result.publicKey.toBase64();
      debugPrint('publicKey (${result.publicKey.format.wireValue}): $display');
    }
  }

  void _toggleEc(bool newValue) {
    setState(() => useEc = newValue);
    _biometricSignature.deleteKeys().then((success) {
      debugPrint('deleteKeys success: $success');
      if (success ?? false) {
        setState(() {
          keyMaterial = null;
          signatureResult = null;
          decryptResult = null;
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
      decryptResult = null;
    });
  }

  Future<void> _createSignature() async {
    if (payload == null || payload!.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('please enter payload')));
      return;
    }
    final validity = await _biometricSignature.biometricKeyExists(
      checkValidity: true,
    );
    debugPrint("Validity : $validity");
    final result = await _biometricSignature.createSignature(
      SignatureOptions(
        payload: payload!,
        promptMessage: 'Sign Payload',
        androidOptions: const AndroidSignatureOptions(
          allowDeviceCredentials: false,
          subtitle: 'Approve the login to continue',
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

  Future<void> _decrypt() async {
    if (payload == null || payload!.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('please enter payload')));
      return;
    }
    if (keyMaterial == null) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('please create keys first')));
      return;
    }

    try {
      // 1. Encrypt the payload using the public key (simulating backend)
      final publicKeyPem = keyMaterial!.publicKey.pemLabel != null
          ? keyMaterial!.publicKey.asString()!
          : '-----BEGIN PUBLIC KEY-----\n${keyMaterial!.publicKey.toBase64()}\n-----END PUBLIC KEY-----';

      final parser = enc.RSAKeyParser();
      final rsaPublicKey = parser.parse(publicKeyPem) as RSAPublicKey;
      final encrypter = enc.Encrypter(enc.RSA(publicKey: rsaPublicKey));
      final encrypted = encrypter.encrypt(payload!);

      // 2. Decrypt using the plugin
      final result = await _biometricSignature.decrypt(
        DecryptionOptions(
          payload: encrypted.base64,
          promptMessage: 'Decrypt Payload',
          androidOptions: const AndroidDecryptionOptions(
            allowDeviceCredentials: false,
            subtitle: 'Approve to decrypt',
          ),
          iosOptions: const IosDecryptionOptions(shouldMigrate: false),
        ),
      );

      setState(() => decryptResult = result?.decryptedData);
      debugPrint('Decrypted: ${result?.decryptedData}');
    } catch (e) {
      debugPrint('Error during encryption/decryption: $e');
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Error: $e')));
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
                if (!useEc && Platform.isAndroid) ...[
                  const SizedBox(width: 16),
                  const Text('Decrypt'),
                  Switch(
                    value: enableAndroidDecryption,
                    onChanged: (v) {
                      setState(() => enableAndroidDecryption = v);
                      // Optional: delete keys when changing this option?
                      _toggleEc(false);
                    },
                  ),
                ],
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
            if (decryptResult != null)
              Text(
                'decrypted: $decryptResult',
                style: const TextStyle(
                  color: Colors.green,
                  fontWeight: FontWeight.bold,
                ),
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
                if ((enableAndroidDecryption || Platform.isIOS) && !useEc)
                  TextButton(onPressed: _decrypt, child: const Text('decrypt')),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
