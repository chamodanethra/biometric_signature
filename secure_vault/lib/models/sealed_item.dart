import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/crypto.dart';

/// Where a vault item came from.
enum ItemOrigin {
  /// Sealed by the provisioning server (it can seal it again).
  server('Provisioning server'),

  /// A note sealed on this device (no other copy exists).
  device('This device'),

  /// Sealed by someone else to this vault's address.
  shared('Shared with you');

  const ItemOrigin(this.label);

  /// Display name.
  final String label;
}

/// How an item's plaintext was sealed.
enum SealFormat {
  /// The plaintext itself is encrypted to the vault key.
  direct('Direct (one public-key ciphertext)'),

  /// The plaintext is AES-256-GCM encrypted under a random data key; only
  /// the data key (as base64 text) is encrypted to the vault key.
  envelope('Envelope (AES-256-GCM, data key sealed to the vault key)');

  const SealFormat(this.label);

  /// Display name.
  final String label;
}

/// Plaintexts up to this many UTF-8 bytes are sealed directly; longer ones
/// use an envelope.
///
/// RSA-2048 OAEP with SHA-256 carries at most 190 bytes. ECIES has no such
/// limit, but using the same rule for every scheme keeps the stored format
/// independent of the key type.
const int directSealLimit = 190;

/// SHA-256 (hex) of the SubjectPublicKeyInfo that [scheme] encrypts to, or
/// `null` for an unsupported scheme.
///
/// Items record this so the app can tell which key can open them.
String? schemeKeyFingerprint(EncryptionScheme scheme) => switch (scheme) {
      EciesScheme(:final publicKeySpki) => sha256Hex(publicKeySpki),
      RsaOaepScheme(:final publicKeySpki) => sha256Hex(publicKeySpki),
      UnsupportedScheme() => null,
    };

/// A short, readable form of a key fingerprint.
String shortFingerprint(String hex) =>
    formatFingerprint(hex, groupSize: 4, maxGroups: 4);

/// A vault item as the device stores it: metadata in the clear, the secret
/// only as ciphertext.
///
/// The title, origin, size and dates are **not** encrypted. Only the
/// secret is, and only the vault key's private half can open it.
class SealedItem {
  /// Creates an item from its parts.
  const SealedItem({
    required this.id,
    required this.title,
    required this.origin,
    required this.format,
    required this.schemeLabel,
    required this.recipientKey,
    required this.plaintextBytes,
    required this.createdAt,
    this.ciphertext,
    this.envelope,
    this.from,
  }) : assert((ciphertext == null) != (envelope == null),
            'Exactly one of ciphertext and envelope must be set');

  /// Encrypts [plaintext] to [scheme].
  ///
  /// Needs only the recipient's public key: no prompt, no private key.
  /// Throws [UnsupportedError] for an [UnsupportedScheme].
  factory SealedItem.seal({
    required String id,
    required String title,
    required ItemOrigin origin,
    required EncryptionScheme scheme,
    required String plaintext,
    required DateTime createdAt,
    String? from,
  }) {
    final recipient = schemeKeyFingerprint(scheme);
    if (recipient == null) throw UnsupportedError(scheme.description);
    final bytes = Uint8List.fromList(utf8.encode(plaintext));
    final direct = bytes.length <= directSealLimit;
    return SealedItem(
      id: id,
      title: title,
      origin: origin,
      format: direct ? SealFormat.direct : SealFormat.envelope,
      schemeLabel: scheme.label,
      recipientKey: recipient,
      plaintextBytes: bytes.length,
      createdAt: createdAt,
      from: from,
      ciphertext: direct ? scheme.encryptToBase64(plaintext) : null,
      envelope: direct ? null : sealEnvelope(scheme, bytes),
    );
  }

  /// Restores an item from [toJson]. Throws [FormatException] when a field
  /// is missing or malformed.
  factory SealedItem.fromJson(Map<String, dynamic> json) {
    try {
      final format = SealFormat.values.byName(json['format'] as String);
      final envelopeJson = json['envelope'];
      final item = SealedItem(
        id: json['id'] as String,
        title: json['title'] as String,
        origin: ItemOrigin.values.byName(json['origin'] as String),
        format: format,
        schemeLabel: json['scheme'] as String? ?? '',
        recipientKey: json['recipientKey'] as String,
        plaintextBytes: json['plaintextBytes'] as int,
        createdAt: DateTime.parse(json['createdAt'] as String),
        from: json['from'] as String?,
        ciphertext:
            format == SealFormat.direct ? json['ciphertext'] as String : null,
        envelope: format == SealFormat.envelope
            ? SealedEnvelope.fromJson(
                (envelopeJson as Map).cast<String, dynamic>())
            : null,
      );
      // Validate the payload encoding once, up front.
      base64.decode(item.devicePayloadBase64);
      return item;
    } on FormatException {
      rethrow;
    } catch (e) {
      throw FormatException('Not a valid vault item: $e');
    }
  }

  /// Stable identifier.
  final String id;

  /// Title (stored in the clear).
  final String title;

  /// Where it came from.
  final ItemOrigin origin;

  /// Direct or envelope.
  final SealFormat format;

  /// The scheme that sealed it, e.g. `ECIES (Android hybrid)`.
  final String schemeLabel;

  /// Fingerprint of the public key it was sealed to.
  final String recipientKey;

  /// Size of the secret in UTF-8 bytes (metadata, in the clear).
  final int plaintextBytes;

  /// When it was sealed.
  final DateTime createdAt;

  /// For [SealFormat.direct]: base64 ciphertext for `decrypt()`.
  final String? ciphertext;

  /// For [SealFormat.envelope]: the envelope.
  final SealedEnvelope? envelope;

  /// Who shared it ([ItemOrigin.shared] only).
  final String? from;

  /// What `decrypt()` receives, as base64: the ciphertext of a direct item,
  /// or the wrapped data key of an envelope. The envelope's AES-GCM content
  /// never goes to the plugin; it is opened in Dart afterwards.
  String get devicePayloadBase64 => ciphertext ?? envelope!.wrappedKeyBase64;

  /// A copy with a different origin / sender.
  SealedItem copyWith({ItemOrigin? origin, String? from}) => SealedItem(
        id: id,
        title: title,
        origin: origin ?? this.origin,
        format: format,
        schemeLabel: schemeLabel,
        recipientKey: recipientKey,
        plaintextBytes: plaintextBytes,
        createdAt: createdAt,
        ciphertext: ciphertext,
        envelope: envelope,
        from: from ?? this.from,
      );

  /// JSON form (all bytes as base64).
  Map<String, dynamic> toJson() => {
        'id': id,
        'title': title,
        'origin': origin.name,
        'format': format.name,
        'scheme': schemeLabel,
        'recipientKey': recipientKey,
        'plaintextBytes': plaintextBytes,
        'createdAt': createdAt.toUtc().toIso8601String(),
        if (from != null) 'from': from,
        if (ciphertext != null) 'ciphertext': ciphertext,
        if (envelope != null) 'envelope': envelope!.toJson(),
      };
}
