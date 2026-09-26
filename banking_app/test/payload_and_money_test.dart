import 'dart:convert';
import 'dart:typed_data';

import 'package:banking_app_example/client/transaction_payload.dart';
import 'package:banking_app_example/money.dart';
import 'package:banking_app_example/server/models.dart';
import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  Map<String, dynamic> fields() => {
        'v': 1,
        'txnId': 'TX-0A1B2C3D',
        'amountCents': 125000,
        'currency': 'USD',
        'fromAccount': 'CHK-4821',
        'payee': 'Alice Chen',
        'payeeAccount': '••3310',
        'nonce': 'bm9uY2U=',
        'iat': 1790000000,
        'exp': 1790000120,
        'tier': 'B',
        'deviceKey': 'ab' * 32,
      };

  Uint8List utf8Bytes(String text) => Uint8List.fromList(utf8.encode(text));

  group('TransactionPayload', () {
    test('decodes canonical bytes and builds the prompt texts', () {
      final p = TransactionPayload.decode(canonicalJsonBytes(fields()));
      expect(p.amountText, r'$1,250.00');
      expect(p.tier, RiskTier.b);
      expect(p.promptMessage, r'Approve $1,250.00 to Alice Chen');
      expect(p.promptSubtitle, r'Pay $1,250.00 to Alice Chen');
      expect(p.promptDescription, 'Ref TX-0A1B2C3D from ••4821');
      expect(p.expiresAt.difference(p.issuedAt), const Duration(minutes: 2));
    });

    test('refuses fields it cannot show', () {
      expect(
          () => TransactionPayload.decode(
              canonicalJsonBytes({...fields(), 'memo': 'hidden'})),
          throwsA(isA<FormatException>()
              .having((e) => e.message, 'message', contains('memo'))));
      expect(
          () => TransactionPayload.decode(
              canonicalJsonBytes(fields()..remove('payee'))),
          throwsFormatException);
    });

    test('refuses non-canonical bytes (duplicate keys, whitespace)', () {
      final canonical = canonicalJson(fields());
      final duplicate = canonical.replaceFirst(
          '"amountCents":125000', '"amountCents":100,"amountCents":125000');
      expect(() => TransactionPayload.decode(utf8Bytes(duplicate)),
          throwsFormatException);
      final spaced = canonical.replaceFirst(':', ': ');
      expect(() => TransactionPayload.decode(utf8Bytes(spaced)),
          throwsFormatException);
    });

    test('refuses wrong types and non-positive amounts', () {
      expect(
          () => TransactionPayload.decode(
              canonicalJsonBytes({...fields(), 'amountCents': '125000'})),
          throwsFormatException);
      expect(
          () => TransactionPayload.decode(
              canonicalJsonBytes({...fields(), 'amountCents': 0})),
          throwsFormatException);
    });

    test('withAmountChanged re-encodes canonically', () {
      final original = canonicalJsonBytes(fields());
      final changed = TransactionPayload.withAmountChanged(original, 900000);
      expect(TransactionPayload.decode(changed).amountCents, 1025000);
      final tampered =
          TransactionPayload.tamperAmount(1)(base64.encode(original)) as String;
      expect(TransactionPayload.decodeBase64(tampered).amountCents, 125001);
      expect(TransactionPayload.tamperAmount(1)(42), 42);
    });
  });

  group('money', () {
    test('formatCents', () {
      expect(formatCents(0), r'$0.00');
      expect(formatCents(5), r'$0.05');
      expect(formatCents(125000), r'$1,250.00');
      expect(formatCents(123456789), r'$1,234,567.89');
      expect(formatCents(-6250), r'-$62.50');
      expect(formatCents(100, signed: true), r'+$1.00');
    });

    test('parseAmountToCents', () {
      expect(parseAmountToCents('1250'), 125000);
      expect(parseAmountToCents(r'$1,250.5'), 125050);
      expect(parseAmountToCents('0.07'), 7);
      expect(parseAmountToCents('12.'), 1200);
      expect(parseAmountToCents('1.234'), isNull);
      expect(parseAmountToCents('-5'), isNull);
      expect(parseAmountToCents('abc'), isNull);
      expect(parseAmountToCents(''), isNull);
    });

    test('maskAccount', () {
      expect(maskAccount('CHK-4821'), '••4821');
      expect(maskAccount('12'), '••12');
    });
  });
}
