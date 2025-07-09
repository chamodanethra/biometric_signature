import 'dart:io';

import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';
import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:biometric_signature/biometric_signature.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('biometric signature test app'),
        ),
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
  String? publicKey;
  String? payload;
  String? signature;

  void _createPublicKey() async {
    final String? publicKey = await _biometricSignature.createKeys(
        androidConfig: AndroidConfig(
            useDeviceCredentials: true,
            signatureType:
                useEc ? AndroidSignatureType.ECDSA : AndroidSignatureType.RSA),
        iosConfig: IosConfig(useDeviceCredentials: false));
    setState(() {
      this.publicKey = publicKey;
    });
    debugPrint("publicKey : $publicKey");
  }

  void _toggleEc(bool newValue) {
    setState(() {
      useEc = newValue;
    });
    _biometricSignature.deleteKeys().then((success) {
      debugPrint("deleteKeys success: $success");
      if (success ?? false) {
        setState(() {
          // ignore: unnecessary_this
          this.publicKey = null;
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
      signature = null;
    });
  }

  void _createSignature() async {
    if (payload == null) {
      debugPrint("payload is null");
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('please enter payload'),
        ),
      );
      return;
    }
    final signature = await _biometricSignature.createSignature(options: {
      "payload": payload!,
      "promptMessage": "Sign Payload",
      "shouldMigrate": "true",
      "allowDeviceCredentials": "true"
    });
    setState(() {
      this.signature = signature;
    });
    debugPrint("signature : $signature");
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (Platform.isAndroid)
              Row(
                children: [
                  Text('use EC'),
                  Switch(value: useEc, onChanged: _toggleEc),
                ],
              ),
            TextButton(
              onPressed: _createPublicKey,
              child: Text('create ${useEc ? 'EC' : 'RSA'} keys'),
            ),
            if (publicKey != null) Text('publicKey: \n$publicKey'),
            const Spacer(),
            if (signature != null) Text('signature: \n$signature'),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    decoration: const InputDecoration(
                      labelText: 'payload',
                    ),
                    onChanged: _payloadChanged,
                  ),
                ),
                TextButton(
                  onPressed: _createSignature,
                  child: Text('sign'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
