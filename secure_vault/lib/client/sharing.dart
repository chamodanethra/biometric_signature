import 'dart:convert';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';

import '../models/sealed_item.dart';
import '../models/vault_key_record.dart';
import 'vault_key_manager.dart';

/// `type` of a vault address JSON.
const String vaultAddressType = 'secure-vault/address';

/// `type` of a sealed-item JSON.
const String sealedItemType = 'secure-vault/sealed-item';

const JsonEncoder _pretty = JsonEncoder.withIndent('  ');

/// A sharing input was malformed, inconsistent or not addressed to us.
class SharingException implements Exception {
  /// Creates the exception.
  const SharingException(this.message);

  /// Explanation for the user.
  final String message;

  @override
  String toString() => message;
}

/// Everything a sender needs to seal items that only one vault can open:
/// the platform, the scheme and the public key. It holds only public data.
class VaultAddress {
  /// Creates an address.
  const VaultAddress({
    required this.platform,
    required this.scheme,
    required this.publicKeyPem,
    required this.isHybridMode,
    this.label,
  });

  /// Parses an address someone shared, and re-derives its scheme.
  ///
  /// The sender never trusts the `scheme` field alone: it resolves the
  /// scheme from the platform and the key with `EncryptionTarget.resolve`
  /// and rejects the address if the two disagree.
  factory VaultAddress.parse(String text) {
    final json = _decodeObject(text, 'vault address');
    if (json['type'] != vaultAddressType) {
      throw const SharingException(
          'This is not a vault address (missing "type": "$vaultAddressType").');
    }
    final platform = DevicePlatform.fromName(json['platform'] as String?);
    final pem = json['publicKeyPem'];
    final schemeJson = json['scheme'];
    if (pem is! String || schemeJson is! Map) {
      throw const SharingException(
          'The address needs "publicKeyPem" and "scheme".');
    }
    final hybrid = json['isHybridMode'] == true;
    final ParsedPublicKey key;
    final EncryptionScheme declared;
    try {
      key = ParsedPublicKey.parse(pem);
      declared = EncryptionScheme.fromJson(schemeJson.cast<String, dynamic>());
    } catch (e) {
      throw SharingException('The address is malformed: $e');
    }
    final derived = EncryptionTarget.resolve(
      platform: platform,
      algorithm: key.algorithm,
      publicKey: hybrid ? null : pem,
      decryptingPublicKey: hybrid ? pem : null,
      decryptingAlgorithm: hybrid ? key.algorithm : null,
      isHybridMode: hybrid,
    );
    if (derived is UnsupportedScheme) {
      throw SharingException(
          'This vault cannot receive sealed items: ${derived.reason}');
    }
    if (canonicalJson(declared.toJson()) != canonicalJson(derived.toJson())) {
      throw const SharingException(
          'The address is inconsistent: its "scheme" does not match its '
          'platform and public key.');
    }
    return VaultAddress(
      platform: platform,
      scheme: derived,
      publicKeyPem: pem,
      isHybridMode: hybrid,
      label: json['label'] as String?,
    );
  }

  /// Recipient platform.
  final DevicePlatform platform;

  /// How to seal for this vault.
  final EncryptionScheme scheme;

  /// The key items are sealed to, as PEM (for Android hybrid mode this is
  /// `decryptingPublicKey`, otherwise `publicKey`).
  final String publicKeyPem;

  /// Android hybrid mode.
  final bool isHybridMode;

  /// Optional display name.
  final String? label;

  /// Fingerprint of [publicKeyPem]'s SPKI.
  String get fingerprint => schemeKeyFingerprint(scheme) ?? '';

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'type': vaultAddressType,
        'v': 1,
        if (label != null) 'label': label,
        'platform': platform.name,
        'isHybridMode': isHybridMode,
        'scheme': scheme.toJson(),
        'publicKeyPem': publicKeyPem,
        'fingerprint': fingerprint,
      };

  /// Pretty JSON for copying.
  String encode() => _pretty.convert(toJson());
}

/// Builds this device's address from `getKeyInfo(keyFormat: KeyFormat.pem)`.
///
/// Throws [SharingException] if the key is missing, cannot decrypt, or is
/// not the key the server registered.
Future<VaultAddress> buildVaultAddress({
  required BiometricSignature api,
  required DevicePlatform platform,
  required VaultKeyRecord record,
  String? label,
}) async {
  final info = await api.getKeyInfo(
    keyAlias: VaultKeyManager.alias,
    keyFormat: KeyFormat.pem,
  );
  if (info.exists != true) {
    throw const SharingException('There is no vault key on this device.');
  }
  final hybrid = info.isHybridMode == true;
  final pem = hybrid ? info.decryptingPublicKey : info.publicKey;
  if (pem == null) {
    throw const SharingException(
        'getKeyInfo returned no public key for the vault key. Use the vault '
        'once (reveal an item), then try again.');
  }
  final scheme = EncryptionTarget.resolve(
    platform: platform,
    algorithm: info.algorithm,
    publicKey: info.publicKey,
    decryptingPublicKey: info.decryptingPublicKey,
    decryptingAlgorithm: info.decryptingAlgorithm,
    isHybridMode: info.isHybridMode,
  );
  if (scheme is UnsupportedScheme) throw SharingException(scheme.reason);
  if (schemeKeyFingerprint(scheme) != record.encryptionKeyFingerprint) {
    throw const SharingException(
        'The key on this device is not the registered vault key. '
        'Re-provision first.');
  }
  return VaultAddress(
    platform: platform,
    scheme: scheme,
    publicKeyPem: pem,
    isHybridMode: hybrid,
    label: label,
  );
}

/// Seals [secret] for [to] and returns the sealed-item JSON to send them.
///
/// Pure Dart: it needs only the recipient's public key — no key of our own,
/// no prompt — so it works on any platform, Windows included.
String sealForRecipient(
  VaultAddress to, {
  required String title,
  required String secret,
  required String from,
  DateTime? now,
}) {
  final item = SealedItem.seal(
    id: 'shared-${toHex(secureRandomBytes(6))}',
    title: title,
    origin: ItemOrigin.shared,
    scheme: to.scheme,
    plaintext: secret,
    createdAt: (now ?? DateTime.now()).toUtc(),
    from: from,
  );
  return _pretty.convert({'type': sealedItemType, 'v': 1, ...item.toJson()});
}

/// Parses a sealed-item JSON addressed to the key [myKeyFingerprint].
///
/// Throws [SharingException] when it is malformed or sealed to another key
/// (which could never be decrypted here).
SealedItem parseSealedItem(String text, {required String myKeyFingerprint}) {
  final json = _decodeObject(text, 'sealed item');
  if (json['type'] != sealedItemType) {
    throw const SharingException(
        'This is not a sealed item (missing "type": "$sealedItemType").');
  }
  final SealedItem item;
  try {
    item = SealedItem.fromJson(json).copyWith(origin: ItemOrigin.shared);
  } on FormatException catch (e) {
    throw SharingException('The sealed item is malformed: ${e.message}');
  }
  if (item.recipientKey != myKeyFingerprint) {
    throw SharingException(
        'This item was sealed to key ${shortFingerprint(item.recipientKey)}, '
        'not to this vault (${shortFingerprint(myKeyFingerprint)}). Only the '
        'vault it was sealed to can open it.');
  }
  return item;
}

Map<String, dynamic> _decodeObject(String text, String what) {
  final Object? decoded;
  try {
    decoded = jsonDecode(text.trim());
  } on FormatException {
    throw SharingException('The $what is not valid JSON.');
  }
  if (decoded is! Map) throw SharingException('The $what must be an object.');
  return decoded.cast<String, dynamic>();
}
