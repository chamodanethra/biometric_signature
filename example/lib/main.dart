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
  final _biometricSignaturePlugin = BiometricSignature();

  @override
  void initState() {
    super.initState();
    asyncInit();
  }

  Future<void> asyncInit() async {
    try {
      final String? biometricsType = await _biometricSignaturePlugin.biometricAuthAvailable();
      debugPrint("biometricsType : $biometricsType");
      // if (condition) {
      //   final bool? result = await _biometricSignaturePlugin.deleteKeys();
      // }
      final bool doExist =
          await _biometricSignaturePlugin.biometricKeyExists() ?? false;
      debugPrint("doExist :$doExist");
      if (!doExist) {
        final String? publicKey = await _biometricSignaturePlugin.createKeys();
          debugPrint("publicKey : $publicKey");
      }
      final String? signature = await _biometricSignaturePlugin.createSignature();
      debugPrint("signature : $signature");
    } on PlatformException catch (e) {
      debugPrint(e.message);
      debugPrint(e.details);
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: Text('Running'),
        ),
      ),
    );
  }
}
