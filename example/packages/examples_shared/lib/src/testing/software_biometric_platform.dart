import 'dart:convert';
import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature_platform_interface.dart';
import 'package:pointycastle/api.dart' show SecureRandom;

import '../crypto/ecies.dart';
import '../crypto/oaep.dart';
import '../crypto/software_keys.dart';
import '../encoding/bytes.dart';
import '../encoding/der.dart';
import '../encoding/pem.dart';
import '../platform/device_platform.dart';
import 'rsa_test_keys.dart';
import 'synthetic_attestation.dart';

/// Operations whose result can be scripted with
/// [SoftwareBiometricPlatform.enqueueResult].
enum FakeOperation {
  /// `createKeys`.
  createKeys,

  /// `createSignature` and `createSignatureFromBytes`.
  sign,

  /// `decrypt`.
  decrypt,

  /// `simplePrompt`.
  simplePrompt,
}

/// What the fake returns for `attestationChallenge` on Android when no
/// [SoftwareBiometricPlatform.cannedAttestationChain] is set.
enum FakeAttestationMode {
  /// A structurally real chain signed by [SyntheticAttestation]'s root
  /// (trust it explicitly in tests).
  synthetic,

  /// `notSupported`, like a keystore that cannot attest. As on a device,
  /// an existing key under the alias has already been deleted by then.
  notSupported,
}

/// A call the fake received.
class FakeCall {
  /// Creates a record.
  const FakeCall(this.method, {this.keyAlias, this.arguments = const {}});

  /// Platform-interface method name, e.g. `createKeys`.
  final String method;

  /// Alias passed (`null` = default).
  final String? keyAlias;

  /// Other arguments (configs, formats, prompt message).
  final Map<String, Object?> arguments;

  @override
  String toString() => 'FakeCall($method, alias: $keyAlias)';
}

/// A key held by the fake. Exposes private material for assertions.
class FakeKey {
  FakeKey._({
    required this.alias,
    required this.isRsa,
    required this.requireAuthentication,
    required this.useDeviceCredentials,
    required this.invalidatedByEnrollment,
    required this.enableDecryption,
    this.ecKey,
    this.rsaKey,
    this.decryptingKey,
    this.attestationChain,
  });

  /// Alias (`null` = default).
  final String? alias;

  /// RSA or EC signing key.
  final bool isRsa;

  /// `requireAuthentication` at creation (silent key when `false`).
  final bool requireAuthentication;

  /// `useDeviceCredentials` at creation.
  final bool useDeviceCredentials;

  /// `setInvalidatedByBiometricEnrollment` at creation.
  final bool invalidatedByEnrollment;

  /// `enableDecryption` at creation.
  final bool enableDecryption;

  /// EC signing key (and Apple decryption key).
  final SoftwareEcKeyPair? ecKey;

  /// RSA key (signs and, where enabled, decrypts).
  final SoftwareRsaKeyPair? rsaKey;

  /// Android hybrid-mode decryption key.
  final SoftwareEcKeyPair? decryptingKey;

  /// Attestation chain returned at creation (Android only).
  final List<Uint8List>? attestationChain;

  /// Whether the key was invalidated by a (simulated) enrollment change.
  bool invalidated = false;

  /// SPKI DER of the signing key.
  Uint8List get signingSpki => isRsa ? rsaKey!.spki : ecKey!.spki;
}

/// A software implementation of [BiometricSignaturePlatform] with real
/// cryptography, for tests and demos without a device.
///
/// It mirrors each platform's observable behaviour (algorithms, hybrid
/// mode, formats, error codes) but has no secure hardware and never
/// prompts. Install it with
/// `BiometricSignaturePlatform.instance = SoftwareBiometricPlatform(...)`.
///
/// Simplifications: RSA keys come from a small pool of pre-generated keys
/// (so two RSA aliases may share a key), and enrollment invalidation is
/// approximated (see [simulateBiometricEnrollmentChange]).
class SoftwareBiometricPlatform extends BiometricSignaturePlatform {
  /// Creates the fake.
  SoftwareBiometricPlatform({
    this.simulatedPlatform = DevicePlatform.android,
    this.authenticationTypeToReport = AuthenticationType.biometric,
    this.deviceLockSet = true,
    BiometricAvailability? availability,
    this.cannedAttestationChain,
    this.attestationMode = FakeAttestationMode.synthetic,
    SyntheticAttestation? syntheticAttestation,
    this.attestedPackageName = 'com.example.app',
    this.operationDelay = Duration.zero,
    this.random,
  })  : availability = availability ??
            BiometricAvailability(
              canAuthenticate: true,
              hasEnrolledBiometrics: true,
              availableBiometrics: [
                simulatedPlatform == DevicePlatform.ios
                    ? BiometricType.face
                    : BiometricType.fingerprint,
              ],
            ),
        syntheticAttestation = syntheticAttestation ?? SyntheticAttestation();

  /// Which platform's behaviour to mirror.
  DevicePlatform simulatedPlatform;

  /// `authenticationType` reported for operations that "prompt".
  AuthenticationType authenticationTypeToReport;

  /// Returned by `isDeviceLockSet`; `false` makes authenticated key
  /// creation fail with `passcodeNotSet`.
  bool deviceLockSet;

  /// Returned by `biometricAuthAvailable`.
  BiometricAvailability availability;

  /// Returned as the attestation chain on Android when set (its leaf will
  /// not match the generated key).
  List<Uint8List>? cannedAttestationChain;

  /// Attestation behaviour when [cannedAttestationChain] is `null`.
  FakeAttestationMode attestationMode;

  /// Signs synthetic attestation chains.
  final SyntheticAttestation syntheticAttestation;

  /// Package name put in synthetic attestations.
  String attestedPackageName;

  /// Artificial delay before each operation.
  Duration operationDelay;

  /// Randomness for key generation and signing (defaults to secure).
  final SecureRandom? random;

  /// Every call received, oldest first.
  final List<FakeCall> calls = [];

  final Map<String, FakeKey> _keys = {};
  final Map<FakeOperation, List<(BiometricError, String?)>> _scripted = {};
  static List<SoftwareRsaKeyPair>? _rsaPool;
  static int _rsaNext = 0;

  /// SPKI SHA-256 of the synthetic attestation root: pass it in
  /// `trustedRootSpkiSha256` to make synthetic chains verify.
  String get syntheticRootSpkiSha256 => syntheticAttestation.rootSpkiSha256;

  /// Makes the next [operation] return [code] (FIFO per operation).
  void enqueueResult(FakeOperation operation, BiometricError code,
      {String? message}) {
    (_scripted[operation] ??= []).add((code, message));
  }

  /// The key under [alias], if any.
  FakeKey? keyFor(String? alias) => _keys[_k(alias)];

  /// Aliases with keys (`null` for the default alias).
  List<String?> get aliases =>
      [for (final k in _keys.keys) k.isEmpty ? null : k];

  /// Invalidates the key under [alias] unconditionally: later sign and
  /// decrypt return `keyInvalidated`, `getKeyInfo(checkValidity: true)`
  /// reports `isValid: false`. Returns whether a key existed.
  bool invalidate({String? alias}) {
    final key = _keys[_k(alias)];
    key?.invalidated = true;
    return key != null;
  }

  /// Simulates enrolling a new fingerprint or face: invalidates keys that
  /// require authentication and were created with
  /// `setInvalidatedByBiometricEnrollment` (default `true`). On iOS/macOS,
  /// `useDeviceCredentials` keys survive (the passcode can always unlock
  /// them). Windows keys are unaffected.
  void simulateBiometricEnrollmentChange() {
    if (simulatedPlatform == DevicePlatform.windows) return;
    for (final key in _keys.values) {
      if (!key.requireAuthentication || !key.invalidatedByEnrollment) continue;
      if (simulatedPlatform.isApple && key.useDeviceCredentials) continue;
      key.invalidated = true;
    }
  }

  static String _k(String? alias) => alias ?? '';

  (BiometricError, String?)? _nextScripted(FakeOperation op) {
    final queue = _scripted[op];
    if (queue == null || queue.isEmpty) return null;
    return queue.removeAt(0);
  }

  Future<void> _delay() async {
    if (operationDelay > Duration.zero) {
      await Future<void>.delayed(operationDelay);
    }
  }

  static SoftwareRsaKeyPair _nextRsaKey() {
    final pool = _rsaPool ??= [
      for (final k in rsaTestKeysPkcs1)
        SoftwareRsaKeyPair.fromPkcs1Der(base64.decode(k)),
    ];
    return pool[_rsaNext++ % pool.length];
  }

  String _formatKey(Uint8List spki, KeyFormat format) => switch (format) {
        KeyFormat.base64 || KeyFormat.raw => base64.encode(spki),
        KeyFormat.pem => spkiToPem(spki),
        KeyFormat.hex => toHex(spki),
      };

  /// What `publicKeyBytes` holds on each platform: SPKI DER on Android and
  /// Windows, `SecKeyCopyExternalRepresentation` on Apple (04||X||Y for EC,
  /// PKCS#1 RSAPublicKey for RSA).
  Uint8List _publicKeyBytes(FakeKey key) {
    if (!simulatedPlatform.isApple) return key.signingSpki;
    if (key.isRsa) {
      return DerEncoder.sequence([
        DerEncoder.integer(key.rsaKey!.modulus),
        DerEncoder.integer(key.rsaKey!.publicExponent),
      ]);
    }
    return key.ecKey!.publicKey.uncompressedPoint;
  }

  AuthenticationType _authTypeFor(FakeKey key) {
    if (simulatedPlatform == DevicePlatform.windows) {
      return AuthenticationType.unknown;
    }
    return key.requireAuthentication
        ? authenticationTypeToReport
        : AuthenticationType.unknown;
  }

  @override
  Future<BiometricAvailability> biometricAuthAvailable() async {
    calls.add(const FakeCall('biometricAuthAvailable'));
    return availability;
  }

  @override
  Future<bool> isDeviceLockSet() async {
    calls.add(const FakeCall('isDeviceLockSet'));
    return deviceLockSet;
  }

  @override
  Future<KeyCreationResult> createKeys(
    String? keyAlias,
    CreateKeysConfig? config,
    KeyFormat keyFormat,
    String? promptMessage,
  ) async {
    calls.add(FakeCall('createKeys', keyAlias: keyAlias, arguments: {
      'config': config,
      'keyFormat': keyFormat,
      'promptMessage': promptMessage,
    }));
    await _delay();
    KeyCreationResult error(BiometricError code, String message) =>
        KeyCreationResult(code: code, error: message);

    final scripted = _nextScripted(FakeOperation.createKeys);
    if (scripted != null) {
      return error(scripted.$1, scripted.$2 ?? 'Scripted ${scripted.$1.name}');
    }
    final platform = simulatedPlatform;
    if (platform == DevicePlatform.other) {
      return error(BiometricError.notSupported, 'Unsupported platform');
    }
    final challenge = config?.attestationChallenge;
    if (challenge != null) {
      if (platform != DevicePlatform.android) {
        return error(
            BiometricError.notSupported,
            'Key attestation (attestationChallenge) is not supported on '
            '${platform.label}.');
      }
      if (challenge.isEmpty || challenge.length > 128) {
        return error(BiometricError.invalidInput,
            'attestationChallenge must be 1-128 bytes');
      }
    }
    final exists = _keys.containsKey(_k(keyAlias));
    if (config?.failIfExists == true && exists) {
      return error(BiometricError.keyAlreadyExists,
          'A key with the specified alias already exists');
    }
    final requireAuth = platform == DevicePlatform.windows ||
        (config?.requireAuthentication ?? true);
    if (requireAuth && !deviceLockSet) {
      return platform == DevicePlatform.windows
          ? error(BiometricError.notAvailable,
              'Windows Hello is not configured on this device')
          : error(BiometricError.passcodeNotSet, 'No screen lock configured');
    }
    if (config?.enforceBiometric == true &&
        platform != DevicePlatform.windows) {
      if (availability.hasEnrolledBiometrics == false) {
        return error(BiometricError.notEnrolled, 'No biometrics enrolled');
      }
      if (availability.canAuthenticate == false) {
        return error(BiometricError.notAvailable, 'Biometrics unavailable');
      }
    }

    // Like the plugin, creation replaces any existing key under the alias.
    _keys.remove(_k(keyAlias));

    final isRsa = platform == DevicePlatform.windows ||
        config?.signatureType == SignatureType.rsa;
    final enableDecryption = config?.enableDecryption ?? false;
    final ecKey = isRsa ? null : SoftwareEcKeyPair.generate(random: random);
    final rsaKey = isRsa ? _nextRsaKey() : null;
    final decryptingKey =
        platform == DevicePlatform.android && !isRsa && enableDecryption
            ? SoftwareEcKeyPair.generate(random: random)
            : null;
    final signingSpki = isRsa ? rsaKey!.spki : ecKey!.spki;

    List<Uint8List>? chain;
    if (challenge != null) {
      chain = cannedAttestationChain;
      if (chain == null) {
        if (attestationMode == FakeAttestationMode.notSupported) {
          return error(
              BiometricError.notSupported, 'This keystore cannot attest keys');
        }
        chain = syntheticAttestation.chainFor(
          attestedSpki: signingSpki,
          challenge: challenge,
          properties: SyntheticKeyProperties(
            noAuthRequired: !requireAuth,
            userAuthType: (config?.useDeviceCredentials ?? false) ? 3 : 2,
            packageName: attestedPackageName,
          ),
        );
      }
    }

    final key = FakeKey._(
      alias: keyAlias,
      isRsa: isRsa,
      requireAuthentication: requireAuth,
      useDeviceCredentials: config?.useDeviceCredentials ?? false,
      invalidatedByEnrollment:
          config?.setInvalidatedByBiometricEnrollment ?? true,
      enableDecryption: enableDecryption || platform.isApple,
      ecKey: ecKey,
      rsaKey: rsaKey,
      decryptingKey: decryptingKey,
      attestationChain: chain,
    );
    _keys[_k(keyAlias)] = key;

    final prompted =
        platform == DevicePlatform.windows || config?.enforceBiometric == true;
    return KeyCreationResult(
      publicKey: _formatKey(signingSpki, keyFormat),
      publicKeyBytes: _publicKeyBytes(key),
      code: BiometricError.success,
      algorithm: isRsa ? 'RSA' : 'EC',
      keySize: isRsa ? 2048 : 256,
      decryptingPublicKey: decryptingKey == null
          ? null
          : _formatKey(decryptingKey.spki, keyFormat),
      decryptingAlgorithm: decryptingKey == null ? null : 'EC',
      decryptingKeySize: decryptingKey == null ? null : 256,
      isHybridMode: decryptingKey != null,
      authenticationType: prompted ? _authTypeFor(key) : null,
      attestationCertificateChain: chain,
    );
  }

  @override
  Future<SignatureResult> createSignature(
    String payload,
    String? keyAlias,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    calls.add(FakeCall('createSignature', keyAlias: keyAlias, arguments: {
      'payload': payload,
      'config': config,
      'signatureFormat': signatureFormat,
      'keyFormat': keyFormat,
      'promptMessage': promptMessage,
    }));
    // Android rejects a blank string (Kotlin isBlank); iOS, macOS and
    // Windows reject only an empty one, which _sign covers.
    return _sign(Uint8List.fromList(utf8.encode(payload)), keyAlias,
        signatureFormat, keyFormat,
        rejectAsBlank: simulatedPlatform == DevicePlatform.android &&
            payload.trim().isEmpty);
  }

  @override
  Future<SignatureResult> createSignatureFromBytes(
    Uint8List payload,
    String? keyAlias,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    calls.add(
        FakeCall('createSignatureFromBytes', keyAlias: keyAlias, arguments: {
      'payload': payload,
      'config': config,
      'signatureFormat': signatureFormat,
      'keyFormat': keyFormat,
      'promptMessage': promptMessage,
    }));
    return _sign(payload, keyAlias, signatureFormat, keyFormat);
  }

  Future<SignatureResult> _sign(
    Uint8List message,
    String? keyAlias,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat, {
    bool rejectAsBlank = false,
  }) async {
    await _delay();
    SignatureResult error(BiometricError code, String message) =>
        SignatureResult(code: code, error: message);
    final scripted = _nextScripted(FakeOperation.sign);
    if (scripted != null) {
      return error(scripted.$1, scripted.$2 ?? 'Scripted ${scripted.$1.name}');
    }
    if (message.isEmpty || rejectAsBlank) {
      return error(BiometricError.invalidInput, 'Payload is required');
    }
    final key = _keys[_k(keyAlias)];
    if (key == null) {
      return error(BiometricError.keyNotFound, 'Signing key not found');
    }
    if (key.invalidated) {
      return error(
          BiometricError.keyInvalidated, 'Biometric key has been invalidated');
    }
    final signature = key.isRsa
        ? key.rsaKey!.sign(message)
        : key.ecKey!.sign(message, random: random);
    return SignatureResult(
      signature: signatureFormat == SignatureFormat.hex
          ? toHex(signature)
          : base64.encode(signature),
      signatureBytes: signature,
      publicKey: _formatKey(key.signingSpki, keyFormat),
      code: BiometricError.success,
      algorithm: key.isRsa ? 'RSA' : 'EC',
      keySize: key.isRsa ? 2048 : 256,
      authenticationType: _authTypeFor(key),
    );
  }

  @override
  Future<DecryptResult> decrypt(
    String payload,
    String? keyAlias,
    PayloadFormat payloadFormat,
    DecryptConfig? config,
    String? promptMessage,
  ) async {
    calls.add(FakeCall('decrypt', keyAlias: keyAlias, arguments: {
      'payload': payload,
      'payloadFormat': payloadFormat,
      'config': config,
      'promptMessage': promptMessage,
    }));
    await _delay();
    DecryptResult error(BiometricError code, String message) =>
        DecryptResult(code: code, error: message);
    final platform = simulatedPlatform;
    if (platform == DevicePlatform.windows ||
        platform == DevicePlatform.other) {
      return error(BiometricError.notAvailable,
          'Decryption is not supported on ${platform.label}.');
    }
    final scripted = _nextScripted(FakeOperation.decrypt);
    if (scripted != null) {
      return error(scripted.$1, scripted.$2 ?? 'Scripted ${scripted.$1.name}');
    }
    if (payload.trim().isEmpty) {
      return error(BiometricError.invalidInput, 'Payload is required');
    }
    final key = _keys[_k(keyAlias)];
    if (key == null) {
      return error(BiometricError.keyNotFound, 'Keys not found');
    }
    if (key.invalidated) {
      return error(
          BiometricError.keyInvalidated, 'Biometric key has been invalidated');
    }
    final Uint8List data;
    try {
      data = payloadFormat == PayloadFormat.hex
          ? fromHex(payload)
          : base64.decode(payload.trim());
    } on FormatException {
      return error(BiometricError.invalidInput, 'Invalid payload');
    }

    Uint8List plain;
    try {
      if (platform == DevicePlatform.android) {
        if (key.decryptingKey != null) {
          plain = eciesReferenceDecrypt(
              key.decryptingKey!.d, data, EciesVariant.android);
        } else if (key.isRsa) {
          if (!key.enableDecryption) {
            return error(BiometricError.unknown,
                'Key was not created with enableDecryption');
          }
          plain = rsaOaepDecrypt(
              key: key.rsaKey!,
              ciphertext: data,
              params: RsaOaepParameters.android);
        } else {
          return error(BiometricError.unknown,
              'Decryption not enabled for EC signing-only mode');
        }
      } else if (key.isRsa) {
        plain = rsaOaepDecrypt(
            key: key.rsaKey!,
            ciphertext: data,
            params: RsaOaepParameters.apple);
      } else {
        plain = eciesReferenceDecrypt(key.ecKey!.d, data, EciesVariant.apple);
      }
    } catch (e) {
      return error(BiometricError.unknown, 'Decryption Error: $e');
    }
    final String text;
    try {
      text = utf8.decode(plain);
    } on FormatException {
      return error(BiometricError.unknown, 'Decryption Error: Invalid UTF-8');
    }
    return DecryptResult(
      decryptedData: text,
      code: BiometricError.success,
      authenticationType: _authTypeFor(key),
    );
  }

  @override
  Future<bool> deleteKeys(String? keyAlias) async {
    calls.add(FakeCall('deleteKeys', keyAlias: keyAlias));
    _keys.remove(_k(keyAlias));
    return true;
  }

  @override
  Future<bool> deleteAllKeys() async {
    calls.add(const FakeCall('deleteAllKeys'));
    _keys.clear();
    return true;
  }

  @override
  Future<KeyInfo> getKeyInfo(
    String? keyAlias,
    bool checkValidity,
    KeyFormat keyFormat,
  ) async {
    calls.add(FakeCall('getKeyInfo', keyAlias: keyAlias, arguments: {
      'checkValidity': checkValidity,
      'keyFormat': keyFormat,
    }));
    final key = _keys[_k(keyAlias)];
    if (key == null) return KeyInfo(exists: false);
    final dk = key.decryptingKey;
    return KeyInfo(
      exists: true,
      isValid: checkValidity ? !key.invalidated : null,
      algorithm: key.isRsa ? 'RSA' : 'EC',
      keySize: key.isRsa ? 2048 : 256,
      isHybridMode: dk != null,
      publicKey: _formatKey(key.signingSpki, keyFormat),
      decryptingPublicKey: dk == null ? null : _formatKey(dk.spki, keyFormat),
      decryptingAlgorithm: dk == null ? null : 'EC',
      decryptingKeySize: dk == null ? null : 256,
      attestationCertificateChain: key.attestationChain,
    );
  }

  @override
  Future<SimplePromptResult> simplePrompt(
    String promptMessage,
    SimplePromptConfig? config,
  ) async {
    calls.add(FakeCall('simplePrompt', arguments: {
      'promptMessage': promptMessage,
      'config': config,
    }));
    await _delay();
    final scripted = _nextScripted(FakeOperation.simplePrompt);
    if (scripted != null) {
      return SimplePromptResult(
        success: false,
        code: scripted.$1,
        error: scripted.$2 ?? 'Scripted ${scripted.$1.name}',
      );
    }
    if (availability.canAuthenticate == false &&
        config?.allowDeviceCredentials != true) {
      return SimplePromptResult(
        success: false,
        code: BiometricError.notAvailable,
        error: 'Biometrics unavailable',
      );
    }
    return SimplePromptResult(
      success: true,
      code: BiometricError.success,
      authenticationType: simulatedPlatform == DevicePlatform.windows
          ? AuthenticationType.unknown
          : authenticationTypeToReport,
    );
  }
}
