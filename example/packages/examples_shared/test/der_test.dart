import 'dart:typed_data';

import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('multi-byte tag numbers round-trip (e.g. [701])', () {
    final encoded = DerEncoder.explicit(701, DerEncoder.integerInt(1234));
    expect(encoded.sublist(0, 3), [0xbf, 0x85, 0x3d]);
    final obj = DerObject.parse(encoded);
    expect(obj.tagClass, DerTagClass.contextSpecific);
    expect(obj.tagNumber, 701);
    expect(obj.isContext(701), isTrue);
    expect(obj.explicitInner().asInt(), 1234);
  });

  test('keeps exact raw slices', () {
    final inner = DerEncoder.octetString([1, 2, 3]);
    final seq = DerEncoder.sequence([DerEncoder.integerInt(5), inner]);
    final obj = DerObject.parse(seq);
    expect(obj.encoded, seq);
    expect(obj.children[1].encoded, inner);
    expect(obj.children[1].value, [1, 2, 3]);
  });

  test('integers: zero, negative, high bit, big', () {
    for (final v in [0, 1, 127, 128, 255, 256, -1, -128, -129, 65537]) {
      expect(DerObject.parse(DerEncoder.integerInt(v)).asInt(), v,
          reason: '$v');
    }
    expect(DerEncoder.integerInt(128), [0x02, 0x02, 0x00, 0x80]);
    expect(DerEncoder.integerInt(-128), [0x02, 0x01, 0x80]);
    final big = BigInt.parse('123456789012345678901234567890');
    expect(DerObject.parse(DerEncoder.integer(big)).asBigInt(), big);
    expect(() => DerObject.parse(DerEncoder.integer(big)).asInt(),
        throwsFormatException);
  });

  test('long-form lengths', () {
    final payload = Uint8List(300);
    final encoded = DerEncoder.octetString(payload);
    expect(encoded.sublist(0, 4), [0x04, 0x82, 0x01, 0x2c]);
    expect(DerObject.parse(encoded).asOctetString().length, 300);
  });

  test('OIDs', () {
    for (final oid in [
      '1.2.840.10045.2.1',
      '1.3.6.1.4.1.11129.2.1.17',
      '2.16.840.1.101.3.4.3.18',
      '2.5.29.19',
    ]) {
      expect(DerObject.parse(DerEncoder.oid(oid)).asOid(), oid);
    }
    expect(DerEncoder.oid('1.2.840.113549'),
        [0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]);
  });

  test('booleans, strictness flag, NULL, enumerated, bit string', () {
    expect(DerObject.parse(DerEncoder.boolean(true)).asBool(), isTrue);
    final lax = DerObject.parse(Uint8List.fromList([0x01, 0x01, 0x01]));
    expect(lax.asBool(), isTrue);
    expect(lax.isStrictDerBoolean, isFalse);
    DerObject.parse(DerEncoder.nullValue()).asNull();
    expect(DerObject.parse(DerEncoder.enumerated(2)).asEnumerated(), 2);
    final bits = DerObject.parse(DerEncoder.bitString([0xff], unusedBits: 1))
        .asBitString();
    expect(bits.unusedBits, 1);
    expect(bits.bytes, [0xff]);
  });

  test('strings and times', () {
    expect(DerObject.parse(DerEncoder.utf8String('héllo')).asString(), 'héllo');
    expect(DerObject.parse(DerEncoder.printableString('US')).asString(), 'US');
    final t = DateTime.utc(2024, 9, 11, 18, 28, 56);
    expect(DerObject.parse(DerEncoder.time(t)).asTime(), t);
    final far = DateTime.utc(2106, 2, 7, 6, 28, 15);
    final encoded = DerEncoder.time(far);
    expect(encoded[0], DerTag.generalizedTime);
    expect(DerObject.parse(encoded).asTime(), far);
    // UTCTime years >= 50 are 19xx.
    final utc1970 = DerObject.parse(
        Uint8List.fromList([0x17, 0x0d, ...'700101000000Z'.codeUnits]));
    expect(utc1970.asTime(), DateTime.utc(1970));
  });

  test('SET OF is sorted', () {
    final set = DerEncoder.setOf([
      DerEncoder.integerInt(3),
      DerEncoder.integerInt(1),
      DerEncoder.integerInt(2),
    ]);
    expect(DerObject.parse(set).asSet().map((e) => e.asInt()), [1, 2, 3]);
  });

  group('rejects malformed input with DerFormatException', () {
    final cases = <String, List<int>>{
      'empty': [],
      'truncated value': [0x04, 0x05, 1, 2],
      'truncated length': [0x04, 0x82, 0x01],
      'indefinite length': [0x30, 0x80, 0x00, 0x00],
      'trailing data': [0x05, 0x00, 0x00],
      'truncated tag': [0x1f],
      'huge length': [0x04, 0x85, 1, 1, 1, 1, 1],
    };
    cases.forEach((name, bytes) {
      test(name, () {
        expect(() => DerObject.parse(Uint8List.fromList(bytes)),
            throwsA(isA<DerFormatException>()));
      });
    });

    test('type mismatches', () {
      final obj = DerObject.parse(DerEncoder.integerInt(1));
      expect(obj.asOctetString, throwsA(isA<DerFormatException>()));
      expect(obj.asSequence, throwsA(isA<DerFormatException>()));
      expect(obj.explicitInner, throwsA(isA<DerFormatException>()));
    });
  });
}
