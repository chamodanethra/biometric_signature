import 'dart:convert';
import 'dart:typed_data';

/// Thrown when bytes are not valid DER for the requested operation.
class DerFormatException extends FormatException {
  /// Creates an exception with a human-readable [message].
  const DerFormatException(super.message, [super.source, super.offset]);

  @override
  String toString() => 'DerFormatException: $message';
}

/// The class bits of a DER identifier octet.
enum DerTagClass {
  /// Universal types (INTEGER, SEQUENCE, …).
  universal,

  /// Application-specific tags.
  application,

  /// Context-specific tags such as `[0]` or `[701]`.
  contextSpecific,

  /// Private tags.
  private,
}

/// Universal tag numbers used by this package.
abstract final class DerTag {
  /// BOOLEAN.
  static const int boolean = 1;

  /// INTEGER.
  static const int integer = 2;

  /// BIT STRING.
  static const int bitString = 3;

  /// OCTET STRING.
  static const int octetString = 4;

  /// NULL.
  static const int nullTag = 5;

  /// OBJECT IDENTIFIER.
  static const int oid = 6;

  /// ENUMERATED.
  static const int enumerated = 10;

  /// UTF8String.
  static const int utf8String = 12;

  /// SEQUENCE / SEQUENCE OF.
  static const int sequence = 16;

  /// SET / SET OF.
  static const int set = 17;

  /// PrintableString.
  static const int printableString = 19;

  /// TeletexString (T61String), decoded as Latin-1.
  static const int teletexString = 20;

  /// IA5String.
  static const int ia5String = 22;

  /// UTCTime.
  static const int utcTime = 23;

  /// GeneralizedTime.
  static const int generalizedTime = 24;

  /// UniversalString (UTF-32BE).
  static const int universalString = 28;

  /// BMPString (UTF-16BE).
  static const int bmpString = 30;
}

/// A BIT STRING value: the payload bytes and the number of unused bits in the
/// last byte.
class DerBitString {
  /// Creates a bit string.
  const DerBitString(this.bytes, this.unusedBits);

  /// The payload bytes (without the leading "unused bits" octet).
  final Uint8List bytes;

  /// Number of unused trailing bits in the last byte (0–7).
  final int unusedBits;
}

/// One parsed DER TLV. Keeps the exact encoded bytes, which signature checks
/// over a certificate's TBS portion need.
class DerObject {
  DerObject._({
    required this.tagClass,
    required this.constructed,
    required this.tagNumber,
    required this.encoded,
    required this.headerLength,
  });

  /// Parses exactly one DER object from [bytes]; trailing bytes are an error.
  factory DerObject.parse(Uint8List bytes) {
    final result = _parseAt(bytes, 0, 0);
    if (result.encoded.length != bytes.length) {
      throw DerFormatException(
        'Trailing data after DER object '
        '(${bytes.length - result.encoded.length} bytes)',
      );
    }
    return result;
  }

  /// Parses a concatenation of DER objects.
  static List<DerObject> parseAll(Uint8List bytes) => _parseList(bytes, 0);

  /// The tag class.
  final DerTagClass tagClass;

  /// Whether the constructed bit is set.
  final bool constructed;

  /// The tag number (may be larger than 30 for multi-byte tags).
  final int tagNumber;

  /// The complete TLV encoding (a view into the source buffer).
  final Uint8List encoded;

  /// Length of the identifier + length octets.
  final int headerLength;

  /// The content octets (a view into the source buffer).
  Uint8List get value => Uint8List.sublistView(encoded, headerLength);

  List<DerObject>? _children;

  /// Child objects of a constructed value (parsed lazily).
  List<DerObject> get children {
    if (!constructed) {
      throw DerFormatException('Tag $tagDescription is not constructed');
    }
    return _children ??= _parseList(value, _depth + 1);
  }

  int _depth = 0;

  /// Whether this is a universal SEQUENCE.
  bool get isSequence => isUniversal(DerTag.sequence);

  /// Whether this is a universal SET.
  bool get isSet => isUniversal(DerTag.set);

  /// Whether this is universal tag [number].
  bool isUniversal(int number) =>
      tagClass == DerTagClass.universal && tagNumber == number;

  /// Whether this is context-specific tag `[number]`.
  bool isContext(int number) =>
      tagClass == DerTagClass.contextSpecific && tagNumber == number;

  /// A short description such as `SEQUENCE` or `[701]`.
  String get tagDescription => switch (tagClass) {
        DerTagClass.universal => 'UNIVERSAL $tagNumber',
        DerTagClass.application => 'APPLICATION $tagNumber',
        DerTagClass.contextSpecific => '[$tagNumber]',
        DerTagClass.private => 'PRIVATE $tagNumber',
      };

  void _expectUniversal(int number, String name) {
    if (!isUniversal(number)) {
      throw DerFormatException('Expected $name, found $tagDescription');
    }
  }

  /// The single inner object of an EXPLICIT context tag.
  DerObject explicitInner() {
    if (tagClass != DerTagClass.contextSpecific || !constructed) {
      throw DerFormatException(
        'Expected an explicit context tag, found $tagDescription',
      );
    }
    final inner = children;
    if (inner.length != 1) {
      throw DerFormatException(
        'Explicit tag $tagDescription must wrap exactly one value, '
        'found ${inner.length}',
      );
    }
    return inner.single;
  }

  /// Children of a SEQUENCE.
  List<DerObject> asSequence() {
    _expectUniversal(DerTag.sequence, 'SEQUENCE');
    return children;
  }

  /// Children of a SET.
  List<DerObject> asSet() {
    _expectUniversal(DerTag.set, 'SET');
    return children;
  }

  /// INTEGER as a [BigInt] (two's complement).
  BigInt asBigInt() {
    _expectUniversal(DerTag.integer, 'INTEGER');
    return _decodeSignedInteger(value);
  }

  /// INTEGER as an [int]; throws if it does not fit in 53 bits.
  int asInt() => _toSafeInt(asBigInt(), 'INTEGER');

  /// ENUMERATED as an [int].
  int asEnumerated() {
    _expectUniversal(DerTag.enumerated, 'ENUMERATED');
    return _toSafeInt(_decodeSignedInteger(value), 'ENUMERATED');
  }

  /// BOOLEAN. Any non-zero byte is `true`; see [isStrictDerBoolean].
  bool asBool() {
    _expectUniversal(DerTag.boolean, 'BOOLEAN');
    if (value.length != 1) {
      throw const DerFormatException('BOOLEAN must be exactly one byte');
    }
    return value[0] != 0;
  }

  /// Whether a BOOLEAN uses the DER encodings 0x00 / 0xFF only.
  bool get isStrictDerBoolean =>
      isUniversal(DerTag.boolean) &&
      value.length == 1 &&
      (value[0] == 0x00 || value[0] == 0xff);

  /// Validates a NULL.
  void asNull() {
    _expectUniversal(DerTag.nullTag, 'NULL');
    if (value.isNotEmpty) {
      throw const DerFormatException('NULL must have empty content');
    }
  }

  /// OCTET STRING content.
  Uint8List asOctetString() {
    _expectUniversal(DerTag.octetString, 'OCTET STRING');
    return value;
  }

  /// BIT STRING content.
  DerBitString asBitString() {
    _expectUniversal(DerTag.bitString, 'BIT STRING');
    if (value.isEmpty) {
      throw const DerFormatException('BIT STRING is empty');
    }
    final unused = value[0];
    if (unused > 7 || (value.length == 1 && unused != 0)) {
      throw const DerFormatException('Invalid BIT STRING unused-bits octet');
    }
    return DerBitString(Uint8List.sublistView(value, 1), unused);
  }

  /// OBJECT IDENTIFIER in dotted form, e.g. `1.2.840.10045.2.1`.
  String asOid() {
    _expectUniversal(DerTag.oid, 'OBJECT IDENTIFIER');
    return decodeOid(value);
  }

  /// A character string (UTF8, Printable, IA5, Teletex, BMP, Universal).
  String asString() {
    if (tagClass != DerTagClass.universal) {
      throw DerFormatException('Expected a string, found $tagDescription');
    }
    switch (tagNumber) {
      case DerTag.utf8String:
        return utf8.decode(value);
      case DerTag.printableString:
      case DerTag.ia5String:
        return ascii.decode(value, allowInvalid: true);
      case DerTag.teletexString:
        return latin1.decode(value);
      case DerTag.bmpString:
        if (value.length.isOdd) {
          throw const DerFormatException('BMPString has odd length');
        }
        final units = <int>[];
        for (var i = 0; i < value.length; i += 2) {
          units.add((value[i] << 8) | value[i + 1]);
        }
        return String.fromCharCodes(units);
      case DerTag.universalString:
        if (value.length % 4 != 0) {
          throw const DerFormatException('UniversalString length not /4');
        }
        final runes = <int>[];
        for (var i = 0; i < value.length; i += 4) {
          runes.add((value[i] << 24) |
              (value[i + 1] << 16) |
              (value[i + 2] << 8) |
              value[i + 3]);
        }
        return String.fromCharCodes(runes);
      default:
        throw DerFormatException('Expected a string, found $tagDescription');
    }
  }

  /// UTCTime or GeneralizedTime as a UTC [DateTime].
  DateTime asTime() {
    if (isUniversal(DerTag.utcTime)) {
      return _parseUtcTime(ascii.decode(value));
    }
    if (isUniversal(DerTag.generalizedTime)) {
      return _parseGeneralizedTime(ascii.decode(value));
    }
    throw DerFormatException('Expected a time, found $tagDescription');
  }
}

const int _maxDepth = 32;

List<DerObject> _parseList(Uint8List bytes, int depth) {
  if (depth > _maxDepth) {
    throw const DerFormatException('DER nesting too deep');
  }
  final out = <DerObject>[];
  var offset = 0;
  while (offset < bytes.length) {
    final obj = _parseAt(bytes, offset, depth);
    out.add(obj);
    offset += obj.encoded.length;
  }
  return out;
}

DerObject _parseAt(Uint8List bytes, int start, int depth) {
  var offset = start;
  if (offset >= bytes.length) {
    throw DerFormatException('Unexpected end of data', null, offset);
  }
  final first = bytes[offset++];
  final tagClass = DerTagClass.values[first >> 6];
  final constructed = (first & 0x20) != 0;
  var tagNumber = first & 0x1f;
  if (tagNumber == 0x1f) {
    // High tag number form: base-128, most significant group first.
    tagNumber = 0;
    var count = 0;
    while (true) {
      if (offset >= bytes.length) {
        throw DerFormatException('Truncated tag number', null, offset);
      }
      final b = bytes[offset++];
      if (count == 0 && b == 0x80) {
        throw DerFormatException('Non-minimal tag number', null, offset);
      }
      tagNumber = (tagNumber << 7) | (b & 0x7f);
      count++;
      if (count > 4) {
        throw DerFormatException('Tag number too large', null, offset);
      }
      if ((b & 0x80) == 0) break;
    }
    if (tagNumber < 0x1f) {
      throw DerFormatException('Non-minimal tag number', null, offset);
    }
  }
  if (offset >= bytes.length) {
    throw DerFormatException('Truncated length', null, offset);
  }
  final lengthByte = bytes[offset++];
  int length;
  if (lengthByte < 0x80) {
    length = lengthByte;
  } else if (lengthByte == 0x80) {
    throw DerFormatException(
        'Indefinite length is not allowed in DER', null, offset);
  } else {
    final count = lengthByte & 0x7f;
    if (count > 4) {
      throw DerFormatException('Length too large', null, offset);
    }
    if (offset + count > bytes.length) {
      throw DerFormatException('Truncated length', null, offset);
    }
    length = 0;
    for (var i = 0; i < count; i++) {
      length = (length << 8) | bytes[offset++];
    }
    // Non-minimal long-form lengths are tolerated: some older keystore
    // implementations emit them, and signature checks use the raw bytes.
  }
  final headerLength = offset - start;
  if (offset + length > bytes.length) {
    throw DerFormatException(
      'Value length $length exceeds available ${bytes.length - offset} bytes',
      null,
      offset,
    );
  }
  final obj = DerObject._(
    tagClass: tagClass,
    constructed: constructed,
    tagNumber: tagNumber,
    encoded: Uint8List.sublistView(bytes, start, offset + length),
    headerLength: headerLength,
  );
  obj._depth = depth;
  return obj;
}

BigInt _decodeSignedInteger(Uint8List bytes) {
  if (bytes.isEmpty) {
    throw const DerFormatException('INTEGER has no content');
  }
  // Non-minimal encodings (redundant leading 0x00/0xFF) are tolerated for
  // the same reason as non-minimal lengths.
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  if ((bytes[0] & 0x80) != 0) {
    result -= BigInt.one << (bytes.length * 8);
  }
  return result;
}

final BigInt _maxSafe = BigInt.from(9007199254740991);

int _toSafeInt(BigInt value, String what) {
  if (value > _maxSafe || value < -_maxSafe) {
    throw DerFormatException('$what value too large for int: $value');
  }
  return value.toInt();
}

/// Decodes OID content octets into dotted notation.
String decodeOid(Uint8List bytes) {
  if (bytes.isEmpty) {
    throw const DerFormatException('Empty OBJECT IDENTIFIER');
  }
  final arcs = <BigInt>[];
  var current = BigInt.zero;
  var inArc = false;
  for (final b in bytes) {
    if (!inArc && b == 0x80) {
      throw const DerFormatException('Non-minimal OID arc');
    }
    current = (current << 7) | BigInt.from(b & 0x7f);
    inArc = true;
    if ((b & 0x80) == 0) {
      arcs.add(current);
      current = BigInt.zero;
      inArc = false;
    }
  }
  if (inArc) {
    throw const DerFormatException('Truncated OID arc');
  }
  final first = arcs.first;
  final parts = <String>[];
  if (first < BigInt.from(40)) {
    parts
      ..add('0')
      ..add('$first');
  } else if (first < BigInt.from(80)) {
    parts
      ..add('1')
      ..add('${first - BigInt.from(40)}');
  } else {
    parts
      ..add('2')
      ..add('${first - BigInt.from(80)}');
  }
  parts.addAll(arcs.skip(1).map((a) => '$a'));
  return parts.join('.');
}

DateTime _parseUtcTime(String s) {
  final match =
      RegExp(r'^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$').firstMatch(s);
  if (match == null) {
    throw DerFormatException('Unsupported UTCTime: $s');
  }
  final yy = int.parse(match.group(1)!);
  // RFC 5280: YY >= 50 means 19YY, otherwise 20YY.
  final year = yy >= 50 ? 1900 + yy : 2000 + yy;
  return DateTime.utc(
    year,
    int.parse(match.group(2)!),
    int.parse(match.group(3)!),
    int.parse(match.group(4)!),
    int.parse(match.group(5)!),
    int.parse(match.group(6) ?? '0'),
  );
}

DateTime _parseGeneralizedTime(String s) {
  final match = RegExp(r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$')
      .firstMatch(s);
  if (match == null) {
    throw DerFormatException('Unsupported GeneralizedTime: $s');
  }
  var millis = 0;
  final fraction = match.group(7);
  if (fraction != null) {
    millis = (double.parse('0$fraction') * 1000).floor();
  }
  return DateTime.utc(
    int.parse(match.group(1)!),
    int.parse(match.group(2)!),
    int.parse(match.group(3)!),
    int.parse(match.group(4)!),
    int.parse(match.group(5)!),
    int.parse(match.group(6)!),
    millis,
  );
}

/// Minimal DER encoder: enough to build SubjectPublicKeyInfo, ECDSA
/// signatures, certificates and key-attestation extensions for tests and the
/// fake platform.
abstract final class DerEncoder {
  /// Encodes an arbitrary TLV.
  static Uint8List tlv({
    required DerTagClass tagClass,
    required bool constructed,
    required int tagNumber,
    required List<int> content,
  }) {
    final header = BytesBuilder();
    final classBits = tagClass.index << 6;
    final constructedBit = constructed ? 0x20 : 0;
    if (tagNumber < 0x1f) {
      header.addByte(classBits | constructedBit | tagNumber);
    } else {
      header.addByte(classBits | constructedBit | 0x1f);
      final groups = <int>[];
      var n = tagNumber;
      do {
        groups.insert(0, n & 0x7f);
        n >>= 7;
      } while (n > 0);
      for (var i = 0; i < groups.length; i++) {
        header.addByte(groups[i] | (i < groups.length - 1 ? 0x80 : 0));
      }
    }
    header.add(_encodeLength(content.length));
    return (header..add(content)).toBytes();
  }

  static List<int> _encodeLength(int length) {
    if (length < 0x80) return [length];
    final bytes = <int>[];
    var n = length;
    while (n > 0) {
      bytes.insert(0, n & 0xff);
      n >>= 8;
    }
    return [0x80 | bytes.length, ...bytes];
  }

  static Uint8List _universal(int tag, List<int> content,
          {bool constructed = false}) =>
      tlv(
        tagClass: DerTagClass.universal,
        constructed: constructed,
        tagNumber: tag,
        content: content,
      );

  /// SEQUENCE of already-encoded elements.
  static Uint8List sequence(List<List<int>> elements) =>
      _universal(DerTag.sequence, [for (final e in elements) ...e],
          constructed: true);

  /// SET OF already-encoded elements, sorted as DER requires.
  static Uint8List setOf(List<List<int>> elements) {
    final sorted = [...elements]..sort(_compareBytes);
    return _universal(DerTag.set, [for (final e in sorted) ...e],
        constructed: true);
  }

  static int _compareBytes(List<int> a, List<int> b) {
    for (var i = 0; i < a.length && i < b.length; i++) {
      if (a[i] != b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  }

  /// INTEGER from a [BigInt] (two's complement, minimal).
  static Uint8List integer(BigInt value) =>
      _universal(DerTag.integer, _signedBytes(value));

  /// INTEGER from an [int].
  static Uint8List integerInt(int value) => integer(BigInt.from(value));

  /// ENUMERATED.
  static Uint8List enumerated(int value) =>
      _universal(DerTag.enumerated, _signedBytes(BigInt.from(value)));

  static List<int> _signedBytes(BigInt value) {
    if (value == BigInt.zero) return [0];
    final bytes = <int>[];
    var v = value;
    if (!v.isNegative) {
      while (v > BigInt.zero) {
        bytes.insert(0, (v & BigInt.from(0xff)).toInt());
        v >>= 8;
      }
      if ((bytes.first & 0x80) != 0) bytes.insert(0, 0);
    } else {
      final byteLength = ((-v).bitLength ~/ 8) + 1;
      v = (BigInt.one << (byteLength * 8)) + v;
      for (var i = 0; i < byteLength; i++) {
        bytes.insert(0, (v & BigInt.from(0xff)).toInt());
        v >>= 8;
      }
      while (bytes.length > 1 && bytes[0] == 0xff && (bytes[1] & 0x80) != 0) {
        bytes.removeAt(0);
      }
    }
    return bytes;
  }

  /// BOOLEAN (DER: 0xFF / 0x00).
  static Uint8List boolean(bool value) =>
      _universal(DerTag.boolean, [value ? 0xff : 0x00]);

  /// NULL.
  static Uint8List nullValue() => _universal(DerTag.nullTag, const []);

  /// OCTET STRING.
  static Uint8List octetString(List<int> bytes) =>
      _universal(DerTag.octetString, bytes);

  /// BIT STRING with [unusedBits] unused trailing bits.
  static Uint8List bitString(List<int> bytes, {int unusedBits = 0}) =>
      _universal(DerTag.bitString, [unusedBits, ...bytes]);

  /// OBJECT IDENTIFIER from dotted notation.
  static Uint8List oid(String dotted) {
    final arcs = dotted.split('.').map(BigInt.parse).toList();
    if (arcs.length < 2) {
      throw ArgumentError.value(dotted, 'dotted', 'needs at least two arcs');
    }
    final content = <int>[];
    void addArc(BigInt arc) {
      final groups = <int>[];
      var v = arc;
      do {
        groups.insert(0, (v & BigInt.from(0x7f)).toInt());
        v >>= 7;
      } while (v > BigInt.zero);
      for (var i = 0; i < groups.length; i++) {
        content.add(groups[i] | (i < groups.length - 1 ? 0x80 : 0));
      }
    }

    addArc(arcs[0] * BigInt.from(40) + arcs[1]);
    arcs.skip(2).forEach(addArc);
    return _universal(DerTag.oid, content);
  }

  /// UTF8String.
  static Uint8List utf8String(String value) =>
      _universal(DerTag.utf8String, utf8.encode(value));

  /// PrintableString.
  static Uint8List printableString(String value) =>
      _universal(DerTag.printableString, ascii.encode(value));

  /// UTCTime (years 1950–2049) or GeneralizedTime otherwise, as RFC 5280
  /// requires for certificate validity.
  static Uint8List time(DateTime value) {
    final t = value.toUtc();
    String two(int v) => v.toString().padLeft(2, '0');
    final rest = '${two(t.month)}${two(t.day)}${two(t.hour)}'
        '${two(t.minute)}${two(t.second)}Z';
    if (t.year >= 1950 && t.year < 2050) {
      return _universal(
          DerTag.utcTime, ascii.encode('${two(t.year % 100)}$rest'));
    }
    return _universal(DerTag.generalizedTime,
        ascii.encode('${t.year.toString().padLeft(4, '0')}$rest'));
  }

  /// EXPLICIT context tag `[tagNumber]` wrapping one encoded value.
  static Uint8List explicit(int tagNumber, List<int> inner) => tlv(
        tagClass: DerTagClass.contextSpecific,
        constructed: true,
        tagNumber: tagNumber,
        content: inner,
      );
}
