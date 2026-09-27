import 'dart:convert';

import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('sorts keys recursively and drops whitespace', () {
    expect(
      canonicalJson({
        'b': 1,
        'a': {'z': true, 'y': null},
        'c': [
          3,
          'x',
          {'k': 'v', 'j': 0}
        ],
      }),
      '{"a":{"y":null,"z":true},"b":1,"c":[3,"x",{"j":0,"k":"v"}]}',
    );
  });

  test('is stable regardless of insertion order', () {
    final a = canonicalJson({'purpose': 'login', 'nonce': 'n', 'userId': 'u'});
    final b = canonicalJson({'userId': 'u', 'nonce': 'n', 'purpose': 'login'});
    expect(a, b);
    expect(canonicalJsonBytes({'x': 'é'}), utf8.encode('{"x":"é"}'));
  });

  test('escapes strings like JSON', () {
    expect(canonicalJson({'q': 'a"b\\c\n'}), r'{"q":"a\"b\\c\n"}');
  });

  test('rejects doubles, non-string keys and other types', () {
    expect(() => canonicalJson({'amount': 12.5}), throwsArgumentError);
    expect(() => canonicalJson([1.0]), throwsArgumentError);
    expect(() => canonicalJson({1: 'x'}), throwsArgumentError);
    expect(() => canonicalJson(DateTime(2020)), throwsArgumentError);
  });

  test('large integers keep their exact text', () {
    expect(canonicalJson({'cents': 9007199254740991}),
        '{"cents":9007199254740991}');
    expect(canonicalJson(-5), '-5');
  });
}
