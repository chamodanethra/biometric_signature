import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:encrypt/encrypt.dart' as enc;
import 'package:flutter/material.dart';
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
        appBar: AppBar(title: const Text('Biometric Signature v12.0.0')),
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

  // Settings
  bool useEc = false;
  bool enableDecryption = false;
  KeyFormat _publicKeyFormat = KeyFormat.pem;
  KeyFormat _signatureKeyFormat = KeyFormat.base64;
  SignatureFormat _signatureFormat = SignatureFormat.base64;
  KeyInfo? _keyInfo;
  bool _checkKeyValidity = false;

  // Results
  KeyCreationResult? keyResult;
  SignatureResult? signatureResult;
  DecryptResult? decryptResult;
  SimplePromptResult? simplePromptResult;
  String? payload;
  String? errorMessage;
  bool isLoading = false;
  BiometricAvailability? availability;

  // Simple Prompt options
  bool _allowDeviceCredentials = false;
  BiometricStrength _biometricStrength = BiometricStrength.strong;

  @override
  void initState() {
    super.initState();
    _checkAvailability();
  }

  Future<void> _checkAvailability() async {
    final result = await _biometricSignature.biometricAuthAvailable();
    setState(() {
      availability = result;
    });
  }

  Future<void> _createKeys() async {
    FocusScope.of(context).unfocus();
    setState(() => errorMessage = null);

    try {
      final result = await _biometricSignature.createKeys(
        keyFormat: _publicKeyFormat,
        promptMessage: 'Authenticate to create keys',
        config: CreateKeysConfig(
          useDeviceCredentials: false,
          signatureType: useEc ? SignatureType.ecdsa : SignatureType.rsa,
          setInvalidatedByBiometricEnrollment: true,
          enforceBiometric: true,
          enableDecryption: enableDecryption,
        ),
      );

      if (result.code == BiometricError.success) {
        setState(() => keyResult = result);
      } else {
        setState(
          () => errorMessage = 'Error: ${result.code} - ${result.error}',
        );
      }
    } catch (e) {
      setState(() => errorMessage = e.toString());
    }
  }

  Future<void> _createSignature() async {
    if (payload == null || payload!.isEmpty) {
      _showSnack('Enter payload first');
      return;
    }
    FocusScope.of(context).unfocus();
    setState(() {
      errorMessage = null;
      signatureResult = null;
    });

    try {
      final result = await _biometricSignature.createSignature(
        payload: payload!,
        signatureFormat: _signatureFormat,
        keyFormat: _signatureKeyFormat,
        promptMessage: 'Sign Data',
        config: CreateSignatureConfig(
          allowDeviceCredentials: false,
        ),
      );

      if (result.code == BiometricError.success) {
        setState(() => signatureResult = result);
      } else {
        setState(
          () => errorMessage = 'Error: ${result.code} - ${result.error}',
        );
      }
    } catch (e) {
      setState(() => errorMessage = e.toString());
    }
  }

  Future<void> _decrypt() async {
    if (Platform.isWindows) {
      setState(() {
        errorMessage =
            'Decryption is not supported on Windows. '
            'Windows Hello is designed for authentication and signing only.';
      });
      return;
    }

    if (payload == null || payload!.isEmpty) {
      _showSnack('Enter payload first');
      return;
    }
    FocusScope.of(context).unfocus();
    setState(() {
      errorMessage = null;
      decryptResult = null;
    });

    try {
      // 1) Encrypt payload first (Roundtrip verification)
      final encryptedBase64 = await _encryptPayload(payload!);
      debugPrint(
        '📦 Encrypted: ${encryptedBase64.substring(0, min(40, encryptedBase64.length))}...',
      );

      // 2) Present biometric prompt via plugin (native UI).
      final result = await _biometricSignature.decrypt(
        payload: encryptedBase64,
        payloadFormat: PayloadFormat.base64,
        promptMessage: 'Decrypt Payload',
        config: DecryptConfig(
          allowDeviceCredentials: false,
        ),
      );

      // Only show overlay if we need to do extra processing after auth.
      setState(() {
        isLoading = true;
      });

      setState(() => decryptResult = result);
      if (result.decryptedData != null) {
        debugPrint('✅ Decrypted: ${result.decryptedData}');
      } else {
        debugPrint(
          '❌ Decryption Failed: Code=${result.code}, Error=${result.error}',
        );
        setState(() => errorMessage = 'Decryption Failed: ${result.code}');
      }
    } catch (e, stack) {
      setState(() => errorMessage = e.toString());
      debugPrint('❌ Error: $e\n$stack');
    } finally {
      setState(() => isLoading = false);
    }
  }

  Future<void> _checkKeyExists() async {
    try {
      final info = await _biometricSignature.getKeyInfo(
        checkValidity: _checkKeyValidity,
        keyFormat: _publicKeyFormat,
      );
      setState(() => _keyInfo = info);
      _showSnack(
        'Key exists: ${info.exists}${info.isValid != null ? ', valid: ${info.isValid}' : ''}',
      );
    } catch (e) {
      setState(() => errorMessage = e.toString());
    }
  }

  /// Encrypts payload based on current key type
  Future<String> _encryptPayload(String plaintext) async {
    // useEc is the source of truth for what we requested.
    if (!useEc) {
      return _encryptRsa(plaintext);
    } else {
      // EC - use ECIES
      return _encryptEcies(plaintext);
    }
  }

  /// RSA encryption
  String _encryptRsa(String plaintext) {
    // All platforms now return SPKI (Standard X.509)
    // In Hybrid mode, RSA key is in decryptingPublicKey
    final publicKeyStr =
        keyResult!.decryptingPublicKey ?? keyResult!.publicKey!;
    final publicKeyPem = publicKeyStr.contains('BEGIN PUBLIC KEY')
        ? publicKeyStr
        : '-----BEGIN PUBLIC KEY-----\n$publicKeyStr\n-----END PUBLIC KEY-----';

    final parser = enc.RSAKeyParser();
    final rsaPublicKey = parser.parse(publicKeyPem) as RSAPublicKey;
    final encrypter = enc.Encrypter(enc.RSA(publicKey: rsaPublicKey));
    return encrypter.encrypt(plaintext).base64;
  }

  /// ECIES encryption
  String _encryptEcies(String plaintext) {
    // Parse recipient's public key (handling both PEM and raw Base64 if needed)
    final publicKeyStr =
        keyResult!.decryptingPublicKey ?? keyResult!.publicKey!;
    // Note: _parseEcPublicKeyFromPem handles stripping headers
    final ecPublicKey = _parseEcPublicKeyFromPem(publicKeyStr);

    // Generate ephemeral keypair
    final ephemeralKeyPair = _generateEphemeralKeyPair(ecPublicKey.parameters!);
    final ephemeralPublic = ephemeralKeyPair.publicKey as ECPublicKey;
    final ephemeralPrivate = ephemeralKeyPair.privateKey as ECPrivateKey;

    // ECDH key agreement
    final agreement = ECDHBasicAgreement()..init(ephemeralPrivate);
    final sharedSecret = agreement.calculateAgreement(ecPublicKey);

    // Output: [EphemeralPubKey (Uncompressed 65)] || [Ciphertext + Tag]
    final isApple = Platform.isIOS || Platform.isMacOS;
    final ephemeralPubBytes = ephemeralPublic.Q!.getEncoded(
      false,
    ); // Uncompressed required

    // ECIES Parameters
    // Hypothesis: Apple Standard Mode uses Static Zero IV and binds EphemKey in SharedInfo.
    final sharedInfo = isApple ? ephemeralPubBytes : Uint8List(0);

    Uint8List gcmIv;
    Uint8List aesKey;
    final Uint8List aad;

    if (isApple) {
      // iOS Standard Mode Hypothesis
      // 1. IV is Static Zeros (16 bytes).
      // 2. KDF derives ONLY Key (16 bytes).
      final keySize = 16;
      aesKey = _kdfX963(sharedSecret, keySize, sharedInfo);
      gcmIv = Uint8List(16); // Zero IV
    } else {
      // Android Standard Mode (Derived IV)
      final keySize = 16;
      final ivSize = 12;
      final derived = _kdfX963(sharedSecret, keySize + ivSize, sharedInfo);
      aesKey = derived.sublist(0, keySize);
      gcmIv = derived.sublist(keySize, keySize + ivSize);
    }

    aad = Uint8List(0);

    // AES-GCM encryption
    final cipher = GCMBlockCipher(AESEngine());
    cipher.init(true, AEADParameters(KeyParameter(aesKey), 128, gcmIv, aad));
    final ciphertext = cipher.process(
      Uint8List.fromList(utf8.encode(plaintext)),
    );

    // Construct Payload: [EphemKey] [Ciphertext]
    // Note: Android uses same payload structure
    final payloadParts = [ephemeralPubBytes, ciphertext];

    return base64Encode(
      Uint8List.fromList(payloadParts.expand((x) => x).toList()),
    );
  }

  // ==================== ECIES Helpers ====================

  ECPublicKey _parseEcPublicKeyFromPem(String pem) {
    // Strip headers if present
    final rows = pem
        .split('\n')
        .where((l) => !l.startsWith('-----') && l.trim().isNotEmpty)
        .join('');
    final bytes = base64Decode(rows);
    final params = ECDomainParameters('secp256r1');
    Uint8List pubBytes;

    try {
      final parser = ASN1Parser(bytes);
      final topLevel = parser.nextObject();

      if (topLevel is ASN1Sequence) {
        // SPKI format (Android)
        final bitString = topLevel.elements![1] as ASN1BitString;
        pubBytes = Uint8List.fromList(bitString.stringValues!);
      } else {
        // iOS returns raw bytes (often parses as OctetString due to 0x04 tag)
        pubBytes = bytes;
      }
    } catch (_) {
      // Fallback to raw bytes just in case
      pubBytes = bytes;
    }

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
    try {
      final success = await _biometricSignature.deleteKeys();
      if (success) {
        setState(() {
          keyResult = null;
          signatureResult = null;
          decryptResult = null;
          errorMessage = null;
        });
        _showSnack('Keys deleted');
      } else {
        setState(() => errorMessage = 'Failed to delete keys');
      }
    } catch (e) {
      setState(() => errorMessage = e.toString());
    }
  }

  Future<void> _simplePrompt() async {
    FocusScope.of(context).unfocus();
    setState(() {
      errorMessage = null;
      simplePromptResult = null;
    });

    try {
      final result = await _biometricSignature.simplePrompt(
        promptMessage: 'Authenticate to continue',
        config: SimplePromptConfig(
          subtitle: 'Verify your identity',
          description: 'Simple biometric prompt demo',
          cancelButtonText: 'Cancel',
          allowDeviceCredentials: _allowDeviceCredentials,
          biometricStrength: _biometricStrength,
        ),
      );

      setState(() => simplePromptResult = result);
      if (result.success == true) {
        _showSnack('Authentication successful!');
      } else {
        _showSnack('Authentication failed: ${result.code}');
      }
    } catch (e) {
      setState(() => errorMessage = e.toString());
    }
  }

  void _showSnack(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Availability Info
          if (availability != null)
            Card(
              child: ListTile(
                leading: Icon(
                  (availability!.canAuthenticate ?? false)
                      ? Icons.check_circle
                      : Icons.warning,
                  color: (availability!.canAuthenticate ?? false)
                      ? Colors.green
                      : Colors.orange,
                ),
                title: Text(
                  (availability!.canAuthenticate ?? false)
                      ? 'Biometrics Available'
                      : 'Biometrics Unavailable',
                ),
                subtitle: Text(availability!.availableBiometrics.toString()),
              ),
            ),

          const SizedBox(height: 10),

          // Config
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                children: [
                  Row(
                    children: [
                      // Hide EC toggle on Windows - Windows Hello only supports RSA
                      if (!Platform.isWindows) ...[
                        const Text('Use EC'),
                        Switch(
                          value: useEc,
                          onChanged: (v) => setState(() => useEc = v),
                        ),
                      ],
                      if (Platform.isAndroid) ...[
                        const SizedBox(width: 20),
                        const Text('Decrypt Support'),
                        Switch(
                          value: enableDecryption,
                          onChanged: (v) =>
                              setState(() => enableDecryption = v),
                        ),
                      ],
                    ],
                  ),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Text('Pub Key: '),
                      DropdownButton<KeyFormat>(
                        value: _publicKeyFormat,
                        onChanged: (v) {
                          if (v != null) setState(() => _publicKeyFormat = v);
                        },
                        items: KeyFormat.values
                            .map(
                              (f) => DropdownMenuItem(
                                value: f,
                                child: Text(f.name),
                              ),
                            )
                            .toList(),
                      ),
                    ],
                  ),
                  ElevatedButton(
                    onPressed: _createKeys,
                    child: const Text('Create Keys'),
                  ),
                ],
              ),
            ),
          ),

          if (keyResult != null)
            Card(
              color: Colors.green.shade50,
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Public Key Created:',
                      style: TextStyle(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      keyResult!.publicKey ?? '',
                      style: const TextStyle(
                        fontSize: 10,
                        fontFamily: 'monospace',
                      ),
                    ),
                    if (keyResult!.publicKeyBytes != null)
                      Text(
                        'Bytes: ${keyResult!.publicKeyBytes!.length} (Hex: ${keyResult!.publicKeyBytes!.map((e) => e.toRadixString(16).padLeft(2, '0')).join()})',
                        style: const TextStyle(fontSize: 8, color: Colors.grey),
                      ),
                    if (keyResult!.decryptingPublicKey != null) ...[
                      const SizedBox(height: 8),
                      const Text(
                        'Decrypting Key (Hybrid):',
                        style: TextStyle(fontWeight: FontWeight.bold),
                      ),
                      Text(
                        keyResult!.decryptingPublicKey!,
                        style: const TextStyle(
                          fontSize: 10,
                          fontFamily: 'monospace',
                        ),
                      ),
                      if (keyResult!.decryptingAlgorithm != null)
                        Text(
                          'Alg: ${keyResult!.decryptingAlgorithm}, Size: ${keyResult!.decryptingKeySize}',
                          style: const TextStyle(fontSize: 10),
                        ),
                    ],
                    const SizedBox(height: 8),
                    TextButton.icon(
                      icon: const Icon(Icons.delete, size: 16),
                      label: const Text('Delete Keys'),
                      onPressed: _deleteKeys,
                    ),
                  ],
                ),
              ),
            ),

          const SizedBox(height: 10),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Key Info (getKeyInfo)',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text('Check Validity'),
                      Switch(
                        value: _checkKeyValidity,
                        onChanged: (v) => setState(() => _checkKeyValidity = v),
                      ),
                    ],
                  ),
                  OutlinedButton.icon(
                    onPressed: _checkKeyExists,
                    icon: const Icon(Icons.vpn_key),
                    label: const Text('Get Key Info'),
                  ),
                  if (_keyInfo != null) ...[
                    const Divider(),
                    _buildKeyInfoRow(
                      'Exists',
                      (_keyInfo!.exists ?? false) ? 'Yes ✓' : 'No',
                    ),
                    if (_keyInfo!.isValid != null)
                      _buildKeyInfoRow(
                        'Valid',
                        _keyInfo!.isValid! ? 'Yes ✓' : 'No ✗',
                      ),
                    if (_keyInfo!.algorithm != null)
                      _buildKeyInfoRow('Algorithm', _keyInfo!.algorithm!),
                    if (_keyInfo!.keySize != null)
                      _buildKeyInfoRow('Key Size', '${_keyInfo!.keySize} bits'),
                    if (_keyInfo!.isHybridMode != null)
                      _buildKeyInfoRow(
                        'Hybrid Mode',
                        _keyInfo!.isHybridMode! ? 'Yes' : 'No',
                      ),
                    if (_keyInfo!.publicKey != null) ...[
                      const SizedBox(height: 8),
                      const Text(
                        'Public Key:',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 12,
                        ),
                      ),
                      const SizedBox(height: 4),
                      SelectableText(
                        _keyInfo!.publicKey!,
                        style: const TextStyle(
                          fontSize: 9,
                          fontFamily: 'monospace',
                        ),
                      ),
                    ],
                    if (_keyInfo!.decryptingPublicKey != null) ...[
                      const SizedBox(height: 8),
                      const Text(
                        'Decrypting Key:',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 12,
                        ),
                      ),
                      Text(
                        '${_keyInfo!.decryptingAlgorithm} / ${_keyInfo!.decryptingKeySize} bits',
                        style: const TextStyle(
                          fontSize: 10,
                          color: Colors.grey,
                        ),
                      ),
                      SelectableText(
                        _keyInfo!.decryptingPublicKey!,
                        style: const TextStyle(
                          fontSize: 9,
                          fontFamily: 'monospace',
                        ),
                      ),
                    ],
                  ],
                ],
              ),
            ),
          ),

          const SizedBox(height: 20),

          // Simple Prompt Section
          Card(
            color: Colors.purple.shade50,
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Simple Biometric Prompt',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'Quick authentication without cryptographic operations',
                    style: TextStyle(fontSize: 12, color: Colors.grey),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      const Text('Allow Device Credentials'),
                      Switch(
                        value: _allowDeviceCredentials,
                        onChanged: (v) =>
                            setState(() => _allowDeviceCredentials = v),
                      ),
                    ],
                  ),
                  if (Platform.isAndroid) ...[
                    Row(
                      children: [
                        const Text('Biometric Strength: '),
                        DropdownButton<BiometricStrength>(
                          value: _biometricStrength,
                          onChanged: (v) {
                            if (v != null) {
                              setState(() => _biometricStrength = v);
                            }
                          },
                          items: BiometricStrength.values
                              .map(
                                (s) => DropdownMenuItem(
                                  value: s,
                                  child: Text(s.name),
                                ),
                              )
                              .toList(),
                        ),
                      ],
                    ),
                  ],
                  const SizedBox(height: 8),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: _simplePrompt,
                      icon: const Icon(Icons.fingerprint),
                      label: const Text('Authenticate'),
                    ),
                  ),
                  if (simplePromptResult != null) ...[
                    const SizedBox(height: 12),
                    Builder(
                      builder: (context) {
                        final isSuccess = simplePromptResult!.success ?? false;
                        final Color bgColor;
                        final Color iconColor;
                        final IconData icon;
                        final String title;

                        if (isSuccess) {
                          bgColor = Colors.green.shade100;
                          iconColor = Colors.green;
                          icon = Icons.check_circle;
                          title = 'Authentication Successful';
                        } else {
                          bgColor = Colors.red.shade100;
                          iconColor = Colors.red;
                          icon = Icons.error;
                          title = 'Authentication Failed';
                        }

                        return Container(
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: bgColor,
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Row(
                            children: [
                              Icon(icon, color: iconColor),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      title,
                                      style: const TextStyle(
                                        fontWeight: FontWeight.bold,
                                      ),
                                    ),
                                    Text(
                                      'Code: ${simplePromptResult!.code}',
                                      style: const TextStyle(fontSize: 11),
                                    ),
                                    if (simplePromptResult!.error != null)
                                      Text(
                                        simplePromptResult!.error!,
                                        style: const TextStyle(
                                          fontSize: 11,
                                          color: Colors.red,
                                        ),
                                      ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                        );
                      },
                    ),
                  ],
                ],
              ),
            ),
          ),

          const SizedBox(height: 20),

          TextField(
            decoration: const InputDecoration(
              labelText: 'Payload (Text or Base64)',
            ),
            onChanged: (v) => payload = v,
          ),

          const SizedBox(height: 10),
          Row(
            children: [
              const Text('Sig Format: '),
              DropdownButton<SignatureFormat>(
                value: _signatureFormat,
                onChanged: (v) {
                  if (v != null) setState(() => _signatureFormat = v);
                },
                items: SignatureFormat.values
                    .map((f) => DropdownMenuItem(value: f, child: Text(f.name)))
                    .toList(),
              ),
              const SizedBox(width: 10),
              const Text('Key Format: '),
              DropdownButton<KeyFormat>(
                value: _signatureKeyFormat,
                onChanged: (v) {
                  if (v != null) setState(() => _signatureKeyFormat = v);
                },
                items: KeyFormat.values
                    .map((f) => DropdownMenuItem(value: f, child: Text(f.name)))
                    .toList(),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: FilledButton(
                  onPressed: _createSignature,
                  child: const Text('Sign'),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: FilledButton.tonal(
                  onPressed: _decrypt,
                  child: const Text('Decrypt'),
                ),
              ),
            ],
          ),

          if (errorMessage != null)
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: Text(
                errorMessage!,
                style: const TextStyle(color: Colors.red),
              ),
            ),

          if (signatureResult != null) ...[
            _buildResult(
              'Signature',
              signatureResult!.signature,
              bytes: signatureResult!.signatureBytes,
            ),
            if (signatureResult!.publicKey != null)
              _buildResult('Signer Public Key', signatureResult!.publicKey),
          ],

          if (decryptResult != null)
            _buildResult('Decrypted', decryptResult!.decryptedData),
        ],
      ),
    );
  }

  Widget _buildResult(String title, String? data, {Uint8List? bytes}) {
    return Card(
      margin: const EdgeInsets.only(top: 10),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: const TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 4),
            SelectableText(
              data ?? 'null',
              style: const TextStyle(fontFamily: 'monospace'),
            ),
            if (bytes != null)
              Text(
                'Bytes: ${bytes.length} (Hex: ${bytes.map((e) => e.toRadixString(16).padLeft(2, '0')).join()})',
                style: const TextStyle(fontSize: 8, color: Colors.grey),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildKeyInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(fontSize: 13, color: Colors.grey)),
          Text(
            value,
            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500),
          ),
        ],
      ),
    );
  }
}
