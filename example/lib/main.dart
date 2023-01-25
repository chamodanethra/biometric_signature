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
    initPlatformState();
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> initPlatformState() async {
    // Platform messages may fail, so we use a try/catch PlatformException.
    // We also handle the message potentially returning null.
    try {
      var doExist = await _biometricSignaturePlugin.biometricKeysExist() ?? false;
      debugPrint(doExist.toString());
      if (!doExist) {
        var resp = await _biometricSignaturePlugin.createKeys();
        resp?.keys.forEach((element) {debugPrint("$element : ${resp[element]}");});
      }
      var response =
      await _biometricSignaturePlugin.createSignature();
      response?.keys.forEach((element) {debugPrint("$element : ${response![element]}");});
    } on PlatformException catch(e) {
      debugPrint(e.message);
      debugPrint(e.details);
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;
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
