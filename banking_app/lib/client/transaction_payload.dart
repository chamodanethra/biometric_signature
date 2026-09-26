/// The transfer payload the bank issues and the device signs.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/crypto.dart';

import '../money.dart';
import '../server/models.dart';

/// A decoded, validated transfer payload.
///
/// The app refuses to show — and so to sign — bytes it cannot display
/// faithfully: unknown fields, missing fields, wrong types and
/// non-canonical encodings (e.g. a duplicate `amountCents` key, where a
/// parser would keep one value and a display another) are all rejected.
class TransactionPayload {
  TransactionPayload._({
    required this.bytes,
    required this.txnId,
    required this.amountCents,
    required this.currency,
    required this.fromAccount,
    required this.payee,
    required this.payeeAccount,
    required this.nonce,
    required this.issuedAt,
    required this.expiresAt,
    required this.tier,
    required this.deviceKey,
  });

  /// Decodes and validates [bytes]. Throws [FormatException].
  factory TransactionPayload.decode(Uint8List bytes) {
    final Object? json;
    try {
      json = jsonDecode(utf8.decode(bytes));
    } on FormatException catch (e) {
      throw FormatException('The payload is not UTF-8 JSON: ${e.message}');
    }
    if (json is! Map<String, dynamic>) {
      throw const FormatException('The payload is not a JSON object');
    }
    final Map<String, dynamic> map = json;
    final keys = map.keys.toSet();
    final unknown = keys.difference(fieldNames);
    if (unknown.isNotEmpty) {
      throw FormatException('Unexpected fields ${unknown.join(', ')}: the '
          'app will not sign what it cannot show');
    }
    final missing = fieldNames.difference(keys);
    if (missing.isNotEmpty) {
      throw FormatException('Missing fields ${missing.join(', ')}');
    }
    Uint8List canonical;
    try {
      canonical = canonicalJsonBytes(map);
    } on ArgumentError catch (e) {
      throw FormatException('The payload is not canonical JSON: ${e.message}');
    }
    if (!constantTimeEquals(canonical, bytes)) {
      throw const FormatException(
          'The payload is not canonical JSON (key order, spacing or '
          'duplicate keys): what is shown might differ from what is signed');
    }
    T field<T>(String name) {
      final value = map[name];
      if (value is! T) throw FormatException('"$name" has the wrong type');
      return value;
    }

    if (field<int>('v') != 1) {
      throw const FormatException('Unsupported payload version');
    }
    final amount = field<int>('amountCents');
    if (amount <= 0) throw const FormatException('The amount is not positive');
    DateTime seconds(String name) =>
        DateTime.fromMillisecondsSinceEpoch(field<int>(name) * 1000,
            isUtc: true);
    return TransactionPayload._(
      bytes: Uint8List.fromList(bytes),
      txnId: field<String>('txnId'),
      amountCents: amount,
      currency: field<String>('currency'),
      fromAccount: field<String>('fromAccount'),
      payee: field<String>('payee'),
      payeeAccount: field<String>('payeeAccount'),
      nonce: field<String>('nonce'),
      issuedAt: seconds('iat'),
      expiresAt: seconds('exp'),
      tier: RiskTier.fromLabel(field<String>('tier')),
      deviceKey: field<String>('deviceKey'),
    );
  }

  /// Decodes a base64 payload. Throws [FormatException].
  factory TransactionPayload.decodeBase64(String value) =>
      TransactionPayload.decode(base64.decode(value));

  /// Every field of version 1.
  static const Set<String> fieldNames = {
    'v',
    'txnId',
    'amountCents',
    'currency',
    'fromAccount',
    'payee',
    'payeeAccount',
    'nonce',
    'iat',
    'exp',
    'tier',
    'deviceKey',
  };

  /// The exact bytes to sign.
  final Uint8List bytes;

  /// Transaction id.
  final String txnId;

  /// Amount in cents.
  final int amountCents;

  /// Currency code.
  final String currency;

  /// Debit account id.
  final String fromAccount;

  /// Payee name.
  final String payee;

  /// Masked payee account.
  final String payeeAccount;

  /// Server nonce (base64), single-use.
  final String nonce;

  /// Issue time (`iat`).
  final DateTime issuedAt;

  /// Approval deadline (`exp`).
  final DateTime expiresAt;

  /// Risk tier the bank decided.
  final RiskTier tier;

  /// SHA-256 fingerprint of this device's `device_binding` key.
  final String deviceKey;

  /// e.g. `$1,250.00`.
  String get amountText => formatCents(amountCents, currency: currency);

  /// The bytes as text (canonical JSON).
  String get canonicalText => utf8.decode(bytes);

  /// SHA-256 of [bytes], hex.
  String get sha256 => sha256Hex(bytes);

  /// The prompt title. iOS and macOS show only this text, so it carries the
  /// amount and payee.
  String get promptMessage => 'Approve $amountText to $payee';

  /// Android prompt subtitle.
  String get promptSubtitle => 'Pay $amountText to $payee';

  /// Android prompt description.
  String get promptDescription => 'Ref $txnId from ${maskAccount(fromAccount)}';

  /// Returns [bytes] with `amountCents` increased by [deltaCents],
  /// re-encoded canonically — what an attacker would substitute.
  static Uint8List withAmountChanged(Uint8List bytes, int deltaCents) {
    final json = jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>;
    json['amountCents'] = (json['amountCents'] as int) + deltaCents;
    return canonicalJsonBytes(json);
  }

  /// A `MockTransport.tamper` mutation for a base64 payload field.
  static Object? Function(Object?) tamperAmount(int deltaCents) => (value) {
        if (value is! String) return value;
        try {
          return base64
              .encode(withAmountChanged(base64.decode(value), deltaCents));
        } on Object {
          return value;
        }
      };
}
