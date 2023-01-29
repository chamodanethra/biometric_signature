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
    final response = await _biometricSignaturePlugin.biometricAuthAvailable();
    response?.keys.forEach((element) {
      debugPrint("$element : ${response![element]}");
    });
    // if (condition) {
    //   await _biometricSignaturePlugin.deleteKeys();
    // }
    try {
      final doExist =
          await _biometricSignaturePlugin.biometricKeyExists() ?? false;
      debugPrint(doExist.toString());
      if (!doExist) {
        var resp = await _biometricSignaturePlugin.createKeys();
        resp?.keys.forEach((element) {
          debugPrint("$element : ${resp[element]}");
        });
      }
      final response = await _biometricSignaturePlugin.createSignature();
      response?.keys.forEach((element) {
        debugPrint("$element : ${response![element]}");
      });
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
