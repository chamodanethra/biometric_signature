import 'package:biometric_signature/android_config.dart';
import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:biometric_signature/biometric_signature.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final _biometricSignature = BiometricSignature();

  @override
  void initState() {
    super.initState();
    asyncInit();
  }

  Future<void> asyncInit() async {
    try {
      final String? biometricsType =
          await _biometricSignature.biometricAuthAvailable();
      debugPrint("biometricsType : $biometricsType");
      // if (condition) {
      //   final bool? result = await _biometricSignature.deleteKeys();
      // }
      final bool doExist =
          await _biometricSignature.biometricKeyExists(checkValidity: true) ?? false;
      debugPrint("doExist : $doExist");
      if (!doExist) {
        final String? publicKey = await _biometricSignature.createKeys(
            config: AndroidConfig(useStrongBox: true));
        debugPrint("publicKey : $publicKey");
      }
      final String? signature = await _biometricSignature.createSignature(
          options: {
            "payload": "Biometric payload",
            "promptMessage": "You are Welcome!"
          });
      debugPrint("signature : $signature");
    } on PlatformException catch (e) {
      debugPrint(e.message);
      debugPrint(e.code);
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: const Center(
          child: Text('Running'),
        ),
      ),
    );
  }
}
