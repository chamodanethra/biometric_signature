import 'dart:convert';
import 'dart:typed_data';

/// Serializes [value] as canonical JSON: object keys sorted by UTF-16 code
/// unit, no insignificant whitespace, and only integers as numbers.
///
/// Allowed values: `null`, `bool`, `int`, `String`, `List` and `Map` with
/// `String` keys. Doubles are rejected with an [ArgumentError], because
/// their text form is not stable across languages — encode amounts as
/// integer minor units (cents) instead.
///
/// Use this to build the exact bytes a server issues and a device signs. The
/// server must verify the bytes it issued, never a re-serialization of what
/// the client sent back.
String canonicalJson(Object? value) {
  final buffer = StringBuffer();
  _write(buffer, value, r'$');
  return buffer.toString();
}

/// UTF-8 bytes of [canonicalJson].
Uint8List canonicalJsonBytes(Object? value) =>
    Uint8List.fromList(utf8.encode(canonicalJson(value)));

void _write(StringBuffer out, Object? value, String path) {
  if (value == null) {
    out.write('null');
  } else if (value is bool) {
    out.write(value ? 'true' : 'false');
  } else if (value is int) {
    out.write(value.toString());
  } else if (value is double) {
    throw ArgumentError.value(
      value,
      path,
      'Canonical JSON only allows integers; encode decimals as strings or '
      'integer minor units',
    );
  } else if (value is String) {
    out.write(jsonEncode(value));
  } else if (value is List) {
    out.write('[');
    for (var i = 0; i < value.length; i++) {
      if (i > 0) out.write(',');
      _write(out, value[i], '$path[$i]');
    }
    out.write(']');
  } else if (value is Map) {
    final keys = <String>[];
    for (final key in value.keys) {
      if (key is! String) {
        throw ArgumentError.value(key, path, 'Map keys must be strings');
      }
      keys.add(key);
    }
    keys.sort();
    out.write('{');
    for (var i = 0; i < keys.length; i++) {
      if (i > 0) out.write(',');
      out
        ..write(jsonEncode(keys[i]))
        ..write(':');
      _write(out, value[keys[i]], '$path.${keys[i]}');
    }
    out.write('}');
  } else {
    throw ArgumentError.value(
      value,
      path,
      'Unsupported type ${value.runtimeType} for canonical JSON',
    );
  }
}
