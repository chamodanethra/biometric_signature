import 'dart:convert';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:flutter/foundation.dart';

import 'result_fields.dart';

/// A value passed to a plugin method, rendered both for people (the call
/// log) and as Dart source ("Copy as Dart").
sealed class ArgValue {
  const ArgValue();

  /// Short human-readable form.
  String get display;

  /// A Dart expression producing this value. [indent] is the indentation of
  /// the line the expression starts on (used by multi-line objects).
  String toDart(String indent);

  /// Whether [toDart] uses `dart:convert`.
  bool get needsConvert => false;

  /// Whether [toDart] uses `dart:typed_data`.
  bool get needsTypedData => false;
}

/// A `String` argument.
final class StringArg extends ArgValue {
  /// Creates the argument.
  const StringArg(this.value);

  /// The string.
  final String value;

  @override
  String get display {
    final oneLine = value.replaceAll('\n', r'\n');
    return oneLine.length <= 120
        ? '"$oneLine"'
        : '"${oneLine.substring(0, 117)}…" (${value.length} chars)';
  }

  @override
  String toDart(String indent) => dartStringLiteral(value);
}

/// A `bool` argument.
final class BoolArg extends ArgValue {
  /// Creates the argument.
  const BoolArg(this.value);

  /// The value.
  final bool value;

  @override
  String get display => '$value';

  @override
  String toDart(String indent) => '$value';
}

/// An enum argument, e.g. `KeyFormat.pem`.
final class EnumArg extends ArgValue {
  /// Creates the argument. [typeName] is spelled out because enum
  /// `runtimeType` names are not stable in obfuscated builds.
  const EnumArg(this.typeName, this.value);

  /// Enum type name.
  final String typeName;

  /// The value.
  final Enum value;

  @override
  String get display => '$typeName.${value.name}';

  @override
  String toDart(String indent) => display;
}

/// A `Uint8List` argument, rendered as `base64.decode('…')`.
final class BytesArg extends ArgValue {
  /// Creates the argument.
  const BytesArg(this.value);

  /// The bytes.
  final Uint8List value;

  @override
  String get display => describeBytes(value);

  @override
  String toDart(String indent) => value.isEmpty
      ? 'Uint8List(0)'
      : "base64.decode('${base64.encode(value)}')";

  @override
  bool get needsConvert => value.isNotEmpty;

  @override
  bool get needsTypedData => value.isEmpty;
}

/// A config object argument, e.g. `CreateKeysConfig(...)`.
final class ObjectArg extends ArgValue {
  /// Creates the argument. Fields whose value is `null` are skipped.
  ObjectArg(this.typeName, Map<String, ArgValue?> fields)
      : fields = [
          for (final e in fields.entries)
            if (e.value != null) (e.key, e.value!),
        ];

  /// Class name.
  final String typeName;

  /// Non-null fields, in order.
  final List<(String, ArgValue)> fields;

  @override
  String get display => fields.isEmpty ? '$typeName()' : '$typeName(…)';

  @override
  String toDart(String indent) {
    if (fields.isEmpty) return '$typeName()';
    final inner = '$indent  ';
    final b = StringBuffer('$typeName(\n');
    for (final (name, value) in fields) {
      b.writeln('$inner$name: ${value.toDart(inner)},');
    }
    b.write('$indent)');
    return b.toString();
  }

  @override
  bool get needsConvert => fields.any((f) => f.$2.needsConvert);

  @override
  bool get needsTypedData => fields.any((f) => f.$2.needsTypedData);
}

/// Quotes [value] as a single-quoted Dart string literal.
String dartStringLiteral(String value) {
  final b = StringBuffer("'");
  for (final rune in value.runes) {
    switch (rune) {
      case 0x5C: // backslash
        b.write(r'\\');
      case 0x27: // '
        b.write(r"\'");
      case 0x24: // $
        b.write(r'\$');
      case 0x0A:
        b.write(r'\n');
      case 0x0D:
        b.write(r'\r');
      case 0x09:
        b.write(r'\t');
      default:
        if (rune < 0x20 || rune == 0x7F) {
          b.write('\\u{${rune.toRadixString(16)}}');
        } else {
          b.writeCharCode(rune);
        }
    }
  }
  b.write("'");
  return b.toString();
}

/// Builds a self-contained Dart snippet that repeats a plugin call.
///
/// The output is a complete library: imports plus a `reproduce()` function
/// returning the same future the Explorer awaited.
String renderDartSnippet({
  required String method,
  required String resultType,
  required List<(String, ArgValue)> args,
}) {
  final needsConvert = args.any((a) => a.$2.needsConvert);
  final needsTypedData = args.any((a) => a.$2.needsTypedData);
  final b = StringBuffer();
  if (needsConvert) b.writeln("import 'dart:convert';");
  if (needsTypedData) b.writeln("import 'dart:typed_data';");
  if (needsConvert || needsTypedData) b.writeln();
  b
    ..writeln("import 'package:biometric_signature/biometric_signature.dart';")
    ..writeln()
    ..writeln('/// Repeats a call made in the Biometric Signature Explorer.')
    ..writeln('Future<$resultType> reproduce() {');
  if (args.isEmpty) {
    b.writeln('  return BiometricSignature().$method();');
  } else {
    b.writeln('  return BiometricSignature().$method(');
    for (final (name, value) in args) {
      b.writeln('    $name: ${value.toDart('    ')},');
    }
    b.writeln('  );');
  }
  b.writeln('}');
  return b.toString();
}

/// Flattens [args] into label/value pairs for the call log, expanding
/// config objects into `config.field` rows.
List<(String, String)> flattenArgs(List<(String, ArgValue)> args) => [
      for (final (name, value) in args)
        if (value is ObjectArg && value.fields.isNotEmpty)
          for (final (field, fieldValue) in value.fields)
            ('$name.$field', fieldValue.display)
        else
          (name, value.display),
    ];

/// How a logged call ended.
enum CallOutcome {
  /// Completed with `code: success` (or a result without a code).
  success,

  /// Completed with an error code the user can recover from by retrying.
  transientError,

  /// Completed with another error code.
  error,

  /// Threw (a bug or a missing platform implementation).
  exception,
}

/// One recorded plugin call.
class CallLogEntry {
  /// Creates an entry.
  CallLogEntry({
    required this.id,
    required this.method,
    required this.startedAt,
    required this.duration,
    required this.arguments,
    required this.fields,
    required this.snippet,
    this.code,
    this.error,
    this.exception,
    this.transient = false,
  });

  /// Sequence number (1-based).
  final int id;

  /// Plugin method name, e.g. `createKeys`.
  final String method;

  /// When the call started.
  final DateTime startedAt;

  /// How long the plugin took (including any prompt).
  final Duration duration;

  /// Arguments as label/value pairs.
  final List<(String, String)> arguments;

  /// Every non-null result field.
  final List<ResultField> fields;

  /// "Copy as Dart" source.
  final String snippet;

  /// The result's `code`, if it has one.
  final BiometricError? code;

  /// The result's `error` message, if any.
  final String? error;

  /// The exception thrown, if the call threw.
  final String? exception;

  /// Whether [code] is a transient error.
  final bool transient;

  /// How the call ended.
  CallOutcome get outcome {
    if (exception != null) return CallOutcome.exception;
    if (isSuccessCode(code)) return CallOutcome.success;
    return transient ? CallOutcome.transientError : CallOutcome.error;
  }

  /// Short outcome label: the code name, `ok`, or `exception`.
  String get outcomeLabel {
    if (exception != null) return 'exception';
    if (code != null) return code!.name;
    return fields.isEmpty ? 'ok' : fields.first.preview(40);
  }

  /// Plain-text dump of the call and its result.
  String toText() {
    final b = StringBuffer('#$id $method  (${duration.inMilliseconds} ms)\n');
    for (final (k, v) in arguments) {
      b.writeln('  $k = $v');
    }
    b.writeln('→');
    for (final f in fields) {
      b.writeln('  ${f.name}: ${f.value}');
    }
    if (exception != null) b.writeln('  exception: $exception');
    return b.toString();
  }
}

/// Every plugin call made in this session, oldest first.
class CallLog extends ChangeNotifier {
  /// Creates a log keeping at most [capacity] entries.
  CallLog({this.capacity = 200});

  /// Maximum number of entries kept.
  final int capacity;

  final List<CallLogEntry> _entries = [];
  int _nextId = 1;

  /// Entries, oldest first.
  List<CallLogEntry> get entries => List.unmodifiable(_entries);

  /// Number of entries.
  int get length => _entries.length;

  /// The most recent entry.
  CallLogEntry? get last => _entries.isEmpty ? null : _entries.last;

  /// Allocates the next sequence number.
  int nextId() => _nextId++;

  /// Appends [entry].
  void add(CallLogEntry entry) {
    _entries.add(entry);
    if (_entries.length > capacity) _entries.removeAt(0);
    notifyListeners();
  }

  /// Records an exception thrown by the Explorer's own code (for example
  /// local encryption), so nothing fails silently.
  void addLocalFailure(String operation, Object error) {
    add(CallLogEntry(
      id: nextId(),
      method: operation,
      startedAt: DateTime.now(),
      duration: Duration.zero,
      arguments: const [],
      fields: const [],
      snippet: '// $operation ran in the Explorer, not in the plugin.\n',
      exception: '$error',
    ));
  }

  /// Removes every entry.
  void clear() {
    _entries.clear();
    notifyListeners();
  }
}
