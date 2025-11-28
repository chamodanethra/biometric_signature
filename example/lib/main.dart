import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:encrypt/encrypt.dart' as enc;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/primitives/asn1_bit_string.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/export.dart' hide Padding, State;

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.blue),
      home: Scaffold(
        appBar: AppBar(title: const Text('Biometric Signature Test')),
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

  // Mode selection
  bool useEc = false;
  bool enableDecryption = false;

  // State
  KeyCreationResult? keyMaterial;
  SignatureResult? signatureResult;
  String? decryptResult;
  String? payload;
  String? errorMessage;
  bool isLoading = false;

  /// Returns current mode description
  String get currentMode {
    if (!useEc) return 'RSA';
    if (!enableDecryption) return 'EC (Sign Only)';
    return 'Hybrid EC (Sign + ECIES)';
  }

  /// Check if hybrid mode
  /// Option 1: Use KeyCreationResult.isHybridMode if your class supports it
  /// Option 2: Infer from configuration (Android + EC + decryption enabled)
  bool get isHybridMode {
    if (keyMaterial == null) return false;
    // If KeyCreationResult has isHybridMode field, use it:
    // return keyMaterial!.isHybridMode;
    // Otherwise, infer from configuration:
    return Platform.isAndroid && useEc && enableDecryption;
  }

  Future<void> _createKeys() async {
    // Hide keyboard and clear errors first.
    FocusScope.of(context).unfocus();
    setState(() {
      errorMessage = null;
    });

    try {
      // Do not set isLoading before prompting biometrics — avoid overlay-related flicker.
      final result = await _biometricSignature.createKeys(
        androidConfig: AndroidConfig(
          useDeviceCredentials: false,
          signatureType: useEc
              ? AndroidSignatureType.ECDSA
              : AndroidSignatureType.RSA,
          setInvalidatedByBiometricEnrollment: true,
          enableDecryption: enableDecryption,
        ),
        iosConfig: IosConfig(
          useDeviceCredentials: false,
          signatureType: useEc ? IOSSignatureType.ECDSA : IOSSignatureType.RSA,
          biometryCurrentSet: true,
        ),
        enforceBiometric: true,
      );

      // Optionally show overlay while doing post-key-creation processing.
      setState(() {
        isLoading = true;
      });

      setState(() => keyMaterial = result);

      if (result != null) {
        debugPrint('✅ Keys created ($currentMode)');
        debugPrint('   Algorithm: ${result.algorithm}');
        debugPrint('   Key Size: ${result.keySize}');
        if (Platform.isAndroid && useEc && enableDecryption) {
          debugPrint('   Hybrid Mode: EC signing + ECIES encryption');
        }
      }
    } catch (e) {
      setState(() => errorMessage = e.toString());
      debugPrint('❌ Error creating keys: $e');
    } finally {
      setState(() => isLoading = false);
    }
  }

  void _onModeChanged() {
    // Clear keys when mode changes
    _biometricSignature.deleteKeys().then((success) {
      if (success == true) {
        setState(() {
          keyMaterial = null;
          signatureResult = null;
          decryptResult = null;
          errorMessage = null;
        });
      }
    });
  }

  void _payloadChanged(String value) {
    if (value == payload) return;
    setState(() {
      payload = value;
      signatureResult = null;
      decryptResult = null;
      errorMessage = null;
    });
  }

  Future<void> _createSignature() async {
    if (payload == null || payload!.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Please enter a payload')));
      return;
    }

    // Hide keyboard — avoids layout changes while FaceID prompt animates.
    FocusScope.of(context).unfocus();

    // We don't set isLoading = true before the biometric prompt to avoid
    // drawing a semi-opaque overlay while iOS presents FaceID (causes flicker).
    setState(() {
      errorMessage = null;
    });

    try {
      // Call createSignature directly — the plugin will show native biometric UI.
      final result = await _biometricSignature.createSignature(
        SignatureOptions(
          payload: payload!,
          promptMessage: 'Sign Payload',
          androidOptions: const AndroidSignatureOptions(
            allowDeviceCredentials: false,
            subtitle: 'Approve to sign data',
          ),
          iosOptions: const IosSignatureOptions(shouldMigrate: false),
        ),
      );

      // Only show the app loading overlay for any post-auth processing.
      setState(() {
        isLoading = true;
      });

      // Apply result and update state (this will repaint after prompt dismisses).
      setState(() {
        signatureResult = result;
      });

      if (result != null) {
        debugPrint('✅ Signature created (${result.algorithm})');
      }
    } catch (e) {
      setState(() => errorMessage = e.toString());
      debugPrint('❌ Error signing: $e');
    } finally {
      // Ensure overlay is removed after all work
      setState(() => isLoading = false);
    }
  }

  Future<void> _decrypt() async {
    if (payload == null || payload!.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Please enter a payload')));
      return;
    }

    if (keyMaterial == null) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Please create keys first')));
      return;
    }

    // Hide keyboard before presenting the biometric prompt.
    FocusScope.of(context).unfocus();

    // Clear previous error and do not show the global overlay while FaceID animates.
    setState(() {
      errorMessage = null;
    });

    try {
      // 1) Do any non-auth expensive work first if needed (none here).
      // 2) Call encrypt helper to produce encryptedBase64 (no overlay).
      final encryptedBase64 = await _encryptPayload(payload!);
      debugPrint('📦 Encrypted: ${encryptedBase64.substring(0, 40)}...');

      // 3) Present biometric prompt via plugin (native UI). Avoid overlay while prompt is visible.
      final result = await _biometricSignature.decrypt(
        DecryptionOptions(
          payload: encryptedBase64,
          promptMessage: 'Decrypt Payload',
          androidOptions: const AndroidDecryptionOptions(
            allowDeviceCredentials: false,
            subtitle: 'Approve to decrypt data',
          ),
          iosOptions: const IosDecryptionOptions(shouldMigrate: false),
        ),
      );

      // Only show overlay if we need to do extra processing after auth.
      setState(() {
        isLoading = true;
      });

      setState(() => decryptResult = result?.decryptedData);
      debugPrint('✅ Decrypted: ${result?.decryptedData}');
    } catch (e, stack) {
      setState(() => errorMessage = e.toString());
      debugPrint('❌ Error: $e\n$stack');
    } finally {
      setState(() => isLoading = false);
    }
  }

  /// Encrypts payload based on current key type
  Future<String> _encryptPayload(String plaintext) async {
    final algorithm = keyMaterial!.algorithm;

    if (algorithm == 'RSA') {
      return _encryptRsa(plaintext);
    } else {
      // EC - use ECIES
      if (Platform.isIOS) {
        return _encryptEciesIos(plaintext);
      } else {
        return _encryptEciesDart(plaintext);
      }
    }
  }

  /// RSA encryption
  String _encryptRsa(String plaintext) {
    final publicKeyPem = keyMaterial!.publicKey.pemLabel != null
        ? keyMaterial!.publicKey.asString()!
        : '-----BEGIN PUBLIC KEY-----\n${keyMaterial!.publicKey.toBase64()}\n-----END PUBLIC KEY-----';

    final parser = enc.RSAKeyParser();
    final rsaPublicKey = parser.parse(publicKeyPem) as RSAPublicKey;
    final encrypter = enc.Encrypter(enc.RSA(publicKey: rsaPublicKey));
    return encrypter.encrypt(plaintext).base64;
  }

  /// ECIES encryption using iOS native
  Future<String> _encryptEciesIos(String plaintext) async {
    const platform = MethodChannel('biometric_signature');
    final result = await platform.invokeMethod('testEncrypt', {
      'payload': plaintext,
    });
    return result['encryptedPayload'] as String;
  }

  /// ECIES encryption using Dart (PointyCastle)
  String _encryptEciesDart(String plaintext) {
    // Parse recipient's public key
    final pem = keyMaterial!.publicKey.toPem();
    final ecPublicKey = _parseEcPublicKeyFromPem(pem);

    // Generate ephemeral keypair
    final ephemeralKeyPair = _generateEphemeralKeyPair(ecPublicKey.parameters!);
    final ephemeralPublic = ephemeralKeyPair.publicKey as ECPublicKey;
    final ephemeralPrivate = ephemeralKeyPair.privateKey as ECPrivateKey;

    // ECDH key agreement
    final agreement = ECDHBasicAgreement()..init(ephemeralPrivate);
    final sharedSecret = agreement.calculateAgreement(ecPublicKey);

    // X9.63 KDF -> AES key (16) + IV (12)
    final derived = _kdfX963(sharedSecret, 28, Uint8List(0));
    final aesKey = derived.sublist(0, 16);
    final gcmIv = derived.sublist(16, 28);

    // AES-128-GCM encryption
    final cipher = GCMBlockCipher(AESEngine());
    cipher.init(
      true,
      AEADParameters(KeyParameter(aesKey), 128, gcmIv, Uint8List(0)),
    );
    final ciphertext = cipher.process(
      Uint8List.fromList(utf8.encode(plaintext)),
    );

    // Output: [EphemeralPubKey(65)] || [Ciphertext + Tag]
    final ephemeralPubBytes = ephemeralPublic.Q!.getEncoded(false);
    return base64Encode(
      Uint8List.fromList([...ephemeralPubBytes, ...ciphertext]),
    );
  }

  // ==================== ECIES Helpers ====================

  ECPublicKey _parseEcPublicKeyFromPem(String pem) {
    final rows = pem
        .split('\n')
        .where((l) => !l.startsWith('-----') && l.trim().isNotEmpty)
        .join('');
    final bytes = base64Decode(rows);

    final parser = ASN1Parser(bytes);
    final topLevel = parser.nextObject() as ASN1Sequence;
    final bitString = topLevel.elements![1] as ASN1BitString;
    final pubBytes = bitString.stringValues!;

    final params = ECDomainParameters('secp256r1');
    final q = params.curve.decodePoint(pubBytes)!;
    return ECPublicKey(q, params);
  }

  AsymmetricKeyPair<PublicKey, PrivateKey> _generateEphemeralKeyPair(
    ECDomainParameters params,
  ) {
    final generator = ECKeyGenerator();
    generator.init(
      ParametersWithRandom(ECKeyGeneratorParameters(params), _secureRandom()),
    );
    return generator.generateKeyPair();
  }

  SecureRandom _secureRandom() {
    final rng = FortunaRandom();
    final seed = Uint8List(32);
    final random = Random.secure();
    for (var i = 0; i < 32; i++) {
      seed[i] = random.nextInt(256);
    }
    rng.seed(KeyParameter(seed));
    return rng;
  }

  Uint8List _kdfX963(BigInt sharedSecret, int length, Uint8List sharedInfo) {
    final digest = SHA256Digest();
    final secretBytes = _bigIntToBytes(sharedSecret, 32);
    final result = Uint8List(length);
    var offset = 0;
    var counter = 1;

    while (offset < length) {
      digest.reset();
      digest.update(secretBytes, 0, secretBytes.length);
      digest.updateByte((counter >> 24) & 0xff);
      digest.updateByte((counter >> 16) & 0xff);
      digest.updateByte((counter >> 8) & 0xff);
      digest.updateByte(counter & 0xff);
      digest.update(sharedInfo, 0, sharedInfo.length);

      final hash = Uint8List(digest.digestSize);
      digest.doFinal(hash, 0);

      final toCopy = (length - offset).clamp(0, hash.length);
      result.setRange(offset, offset + toCopy, hash);
      offset += toCopy;
      counter++;
    }
    return result;
  }

  Uint8List _bigIntToBytes(BigInt number, int length) {
    var hex = number.toRadixString(16);
    if (hex.length % 2 != 0) hex = '0$hex';

    final bytes = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }

    if (bytes.length >= length) return bytes.sublist(bytes.length - length);

    final padded = Uint8List(length);
    padded.setRange(length - bytes.length, length, bytes);
    return padded;
  }

  Future<void> _deleteKeys() async {
    final success = await _biometricSignature.deleteKeys();
    debugPrint('🗑️ Delete keys: $success');
    if (success == true) {
      setState(() {
        keyMaterial = null;
        signatureResult = null;
        decryptResult = null;
        errorMessage = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final canDecrypt = enableDecryption || Platform.isIOS;

    return SafeArea(
      child: Stack(
        children: [
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Mode Selection Card
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(12.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Mode: $currentMode',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        Row(
                          children: [
                            FilterChip(
                              label: const Text('EC'),
                              selected: useEc,
                              onSelected: (v) {
                                setState(() => useEc = v);
                                _onModeChanged();
                              },
                            ),
                            const SizedBox(width: 8),
                            FilterChip(
                              label: const Text('Decryption'),
                              selected: enableDecryption,
                              onSelected: (v) {
                                setState(() => enableDecryption = v);
                                _onModeChanged();
                              },
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),

                const SizedBox(height: 12),

                // Key Status Card
                Card(
                  color: keyMaterial != null
                      ? Colors.green.shade50
                      : Colors.grey.shade100,
                  child: Padding(
                    padding: const EdgeInsets.all(12.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Icon(
                              keyMaterial != null
                                  ? Icons.check_circle
                                  : Icons.cancel,
                              color: keyMaterial != null
                                  ? Colors.green
                                  : Colors.grey,
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                keyMaterial != null
                                    ? 'Keys: ${keyMaterial!.algorithm} (${keyMaterial!.keySize} bits)'
                                    : 'No Keys',
                                style: const TextStyle(
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ],
                        ),
                        if (keyMaterial != null && isHybridMode) ...[
                          const SizedBox(height: 4),
                          Text(
                            '🔀 Hybrid: EC signing + EC encryption (ECIES)',
                            style: TextStyle(
                              fontSize: 12,
                              color: Colors.blue.shade700,
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                ),

                const SizedBox(height: 12),

                // Action Buttons
                Row(
                  children: [
                    Expanded(
                      child: FilledButton.icon(
                        onPressed: isLoading ? null : _createKeys,
                        icon: const Icon(Icons.key),
                        label: const Text('Create Keys'),
                      ),
                    ),
                    const SizedBox(width: 8),
                    OutlinedButton.icon(
                      onPressed: !isLoading ? _deleteKeys : null,
                      icon: const Icon(Icons.delete),
                      label: const Text('Delete'),
                    ),
                  ],
                ),

                const SizedBox(height: 20),

                // Payload Input
                TextField(
                  decoration: const InputDecoration(
                    labelText: 'Payload',
                    hintText: 'Enter text to sign/encrypt',
                    border: OutlineInputBorder(),
                  ),
                  onChanged: _payloadChanged,
                ),

                const SizedBox(height: 12),

                // Sign & Decrypt Buttons
                Row(
                  children: [
                    Expanded(
                      child: FilledButton.tonalIcon(
                        onPressed: !isLoading ? _createSignature : null,
                        icon: const Icon(Icons.draw),
                        label: const Text('Sign'),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: FilledButton.icon(
                        onPressed:
                            keyMaterial != null && canDecrypt && !isLoading
                            ? _decrypt
                            : null,
                        icon: const Icon(Icons.lock_open),
                        label: const Text('Decrypt'),
                        style: FilledButton.styleFrom(
                          backgroundColor: Colors.teal,
                        ),
                      ),
                    ),
                  ],
                ),

                const SizedBox(height: 16),

                // Results
                Expanded(
                  child: SingleChildScrollView(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        if (errorMessage != null)
                          _buildResultCard(
                            icon: Icons.error,
                            color: Colors.red,
                            title: 'Error',
                            content: errorMessage!,
                          ),

                        if (signatureResult != null)
                          _buildResultCard(
                            icon: Icons.verified,
                            color: Colors.blue,
                            title: 'Signature (${signatureResult!.algorithm})',
                            content: signatureResult!.signature.toBase64(),
                            isMonospace: true,
                          ),

                        if (decryptResult != null)
                          _buildResultCard(
                            icon: Icons.check_circle,
                            color: Colors.green.shade900,
                            title: 'Decrypted',
                            content: decryptResult!,
                          ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),

          // Loading overlay
          if (isLoading)
            Container(
              color: Colors.black26,
              child: const Center(child: CircularProgressIndicator()),
            ),
        ],
      ),
    );
  }

  Widget _buildResultCard({
    required IconData icon,
    required Color color,
    required String title,
    required String content,
    bool isMonospace = false,
  }) {
    return Card(
      color: color.withOpacity(0.1),
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, color: color, size: 20),
                const SizedBox(width: 8),
                Text(
                  title,
                  style: TextStyle(fontWeight: FontWeight.bold, color: color),
                ),
              ],
            ),
            const SizedBox(height: 8),
            SelectableText(
              content,
              style: TextStyle(
                fontSize: 12,
                fontFamily: isMonospace ? 'monospace' : null,
                color: color.withOpacity(0.8),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
