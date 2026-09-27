import 'dart:convert';
import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:flutter/widgets.dart';

import 'controller_base.dart';
import 'key_alias.dart';

/// Where the Decrypt screen's ciphertext comes from.
enum DecryptSource {
  /// Encrypted here with the scheme resolved from the key.
  encryptHere,

  /// Pasted by the user (e.g. produced by a server).
  paste,
}

/// Largest plaintext for RSA-2048 with OAEP-SHA-256.
const int rsaOaepMaxPlaintextBytes = 190;

/// Decrypt screen: resolves the encryption scheme from the real key,
/// encrypts locally and calls `decrypt`.
class DecryptController extends ExplorerController {
  /// Creates the controller.
  DecryptController(super.state);

  /// Operation id for [resolveScheme].
  static const String resolveOp = 'resolveScheme';

  /// Operation id for [encrypt].
  static const String encryptOp = 'encrypt';

  /// Operation id for [decrypt].
  static const String decryptOp = 'decrypt';

  /// Ciphertext source.
  DecryptSource source = DecryptSource.encryptHere;

  /// Text to encrypt.
  final TextEditingController plaintext =
      TextEditingController(text: 'Vault code: 4-8-15-16-23-42');

  /// Pasted ciphertext (sent verbatim with [payloadFormat]).
  final TextEditingController pasted = TextEditingController();

  /// `payloadFormat`.
  PayloadFormat payloadFormat = PayloadFormat.base64;

  /// `DecryptConfig.allowDeviceCredentials`.
  bool allowDeviceCredentials = false;

  /// `promptMessage`.
  final TextEditingController promptMessage =
      TextEditingController(text: 'Decrypt with your Explorer key');

  /// `DecryptConfig.promptSubtitle`.
  final TextEditingController promptSubtitle = TextEditingController();

  /// `DecryptConfig.promptDescription`.
  final TextEditingController promptDescription = TextEditingController();

  /// `DecryptConfig.cancelButtonText`.
  final TextEditingController cancelButtonText = TextEditingController();

  /// Alias the [scheme] was resolved for.
  KeyAlias? schemeAlias;

  /// The scheme for [schemeAlias].
  EncryptionScheme? scheme;

  /// The `getKeyInfo` result used to resolve [scheme].
  KeyInfo? keyInfo;

  /// Notes about how [scheme] was resolved (fallbacks, caveats).
  List<String> schemeNotes = const [];

  /// Local ciphertext (for [DecryptSource.encryptHere]).
  Uint8List? ciphertext;

  /// The plaintext [ciphertext] encrypts.
  String? encryptedPlaintext;

  /// Why the last [encrypt] produced nothing (e.g. over the RSA limit).
  String? encryptError;

  /// Alias [ciphertext] was made for.
  KeyAlias? ciphertextAlias;

  /// Last `decrypt` result.
  DecryptResult? result;

  /// The payload string sent with [result].
  String? sentPayload;

  /// The format sent with [result].
  PayloadFormat? sentFormat;

  /// The plaintext expected back for [result] (encrypt-here mode only).
  String? expectedPlaintext;

  /// Whether [scheme] belongs to the selected alias.
  bool get schemeIsCurrent =>
      scheme != null && schemeAlias == state.selectedAlias;

  /// UTF-8 length of [plaintext].
  int get plaintextBytes => utf8.encode(plaintext.text).length;

  /// Whether [plaintext] exceeds the RSA-OAEP limit for the current scheme.
  bool get overRsaLimit =>
      schemeIsCurrent &&
      scheme is RsaOaepScheme &&
      plaintextBytes > rsaOaepMaxPlaintextBytes;

  /// Whether [ciphertext] belongs to the selected alias.
  bool get ciphertextIsCurrent =>
      ciphertext != null && ciphertextAlias == state.selectedAlias;

  /// Reads the key with `getKeyInfo` (falling back to the createKeys result
  /// recorded in this session) and resolves the encryption scheme.
  Future<void> resolveScheme() => run(resolveOp, _resolve);

  Future<void> _resolve() async {
    final alias = state.selectedAlias;
    final info = await api.getKeyInfo(keyAlias: alias.value);
    final record = state.recordFor(alias)?.result;
    final notes = <String>[];
    EncryptionScheme resolved;
    if (info.exists != true) {
      resolved = UnsupportedScheme(
          'No key under ${alias.label}. Create one on the Keys screen first.');
    } else {
      var publicKey = info.publicKey;
      if (publicKey == null && record?.publicKey != null) {
        publicKey = record!.publicKey;
        notes.add('getKeyInfo returned no publicKey (an iOS RSA key made by '
            'an older plugin version that has not been used since the '
            'upgrade); using the key createKeys returned in this session.');
      }
      var decryptingPublicKey = info.decryptingPublicKey;
      if (decryptingPublicKey == null &&
          info.isHybridMode == true &&
          record?.decryptingPublicKey != null) {
        decryptingPublicKey = record!.decryptingPublicKey;
        notes.add('Using decryptingPublicKey from the createKeys result.');
      }
      resolved = EncryptionTarget.resolve(
        platform: state.platform,
        algorithm: info.algorithm ?? record?.algorithm,
        publicKey: publicKey,
        decryptingPublicKey: decryptingPublicKey,
        decryptingAlgorithm:
            info.decryptingAlgorithm ?? record?.decryptingAlgorithm,
        isHybridMode: info.isHybridMode,
      );
      final config = state.recordFor(alias)?.config;
      if (resolved is RsaOaepScheme &&
          state.platform == DevicePlatform.android &&
          config != null &&
          config.enableDecryption != true) {
        notes.add('This RSA key was created without enableDecryption, so '
            'the Android keystore will refuse to decrypt with it.');
      }
    }
    schemeAlias = alias;
    keyInfo = info;
    scheme = resolved;
    schemeNotes = notes;
  }

  /// Encrypts [plaintext] locally for the selected key.
  Future<void> encrypt() => run(encryptOp, () async {
        if (!schemeIsCurrent) await _resolve();
        final s = scheme!;
        ciphertext = null;
        encryptError = null;
        if (!s.isSupported) return;
        final text = plaintext.text;
        if (s is RsaOaepScheme && plaintextBytes > rsaOaepMaxPlaintextBytes) {
          encryptError = 'RSA-2048 with OAEP-SHA-256 fits at most '
              '$rsaOaepMaxPlaintextBytes bytes; this text is $plaintextBytes '
              'bytes. Shorten it, or use envelope encryption (encrypt a '
              'random AES key with RSA and the data with AES-GCM).';
          return;
        }
        ciphertext = s.encrypt(text);
        encryptedPlaintext = text;
        ciphertextAlias = state.selectedAlias;
      });

  /// The payload string for [format]. `raw` is base64-decoded by every
  /// platform, so it is sent as base64 text too.
  String? payloadFor(PayloadFormat format) {
    final ct = ciphertext;
    if (ct == null) return null;
    return format == PayloadFormat.hex ? toHex(ct) : base64.encode(ct);
  }

  /// Whether [decrypt] has something to send.
  bool get canDecrypt => source == DecryptSource.paste
      ? pasted.text.trim().isNotEmpty
      : ciphertextIsCurrent;

  /// Calls `decrypt` with the local or pasted ciphertext.
  Future<void> decrypt() => run(decryptOp, () async {
        final alias = state.selectedAlias;
        final String payload;
        String? expected;
        if (source == DecryptSource.paste) {
          payload = pasted.text.trim();
        } else {
          payload = payloadFor(payloadFormat) ?? '';
          expected = encryptedPlaintext;
        }
        await _decrypt(alias, payload, payloadFormat, expected);
      });

  /// Calls `decrypt` with a dummy payload (Windows: shows notAvailable).
  Future<void> decryptAnyway() => run(decryptOp, () async {
        await _decrypt(state.selectedAlias, 'AAAA', PayloadFormat.base64, null);
      });

  Future<void> _decrypt(KeyAlias alias, String payload, PayloadFormat format,
      String? expected) async {
    result = null;
    notifyListeners();
    final r = await api.decrypt(
      payload: payload,
      payloadFormat: format,
      keyAlias: alias.value,
      config: DecryptConfig(
        promptSubtitle: ExplorerController.optionalText(promptSubtitle),
        promptDescription: ExplorerController.optionalText(promptDescription),
        cancelButtonText: ExplorerController.optionalText(cancelButtonText),
        allowDeviceCredentials: allowDeviceCredentials,
      ),
      promptMessage: ExplorerController.optionalText(promptMessage),
    );
    result = r;
    sentPayload = payload;
    sentFormat = format;
    expectedPlaintext = expected;
  }

  @override
  void dispose() {
    plaintext.dispose();
    pasted.dispose();
    promptMessage.dispose();
    promptSubtitle.dispose();
    promptDescription.dispose();
    cancelButtonText.dispose();
    super.dispose();
  }
}
