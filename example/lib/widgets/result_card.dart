import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../state/result_fields.dart';

/// Status chip for a result code (`null` = a result without a code).
class CodeChip extends StatelessWidget {
  /// Creates the chip.
  const CodeChip({super.key, required this.code});

  /// The code.
  final BiometricError? code;

  @override
  Widget build(BuildContext context) {
    final c = code;
    if (isSuccessCode(c)) {
      return const StatusChip(label: 'success', kind: StatusKind.success);
    }
    final transient = guidanceFor(c).isTransient;
    return StatusChip(
      label: c!.name,
      kind: transient ? StatusKind.warning : StatusKind.danger,
    );
  }
}

/// Renders every non-null field of a plugin result: an [ErrorBanner] for
/// error codes, then one row per field, then [children].
class ResultCard extends StatelessWidget {
  /// Creates the card.
  const ResultCard({
    super.key,
    required this.title,
    required this.result,
    this.subtitle,
    this.children = const [],
    this.hideFields = const {},
  });

  /// Card title, e.g. `KeyCreationResult`.
  final String title;

  /// Optional subtitle (alias, duration…).
  final String? subtitle;

  /// The plugin result.
  final Object result;

  /// Extra widgets below the fields.
  final List<Widget> children;

  /// Field names rendered elsewhere by [children].
  final Set<String> hideFields;

  @override
  Widget build(BuildContext context) {
    final code = resultCode(result);
    final error = resultError(result);
    final failed = !isSuccessCode(code);
    final fields = [
      for (final f in resultFields(result))
        if (f.name != 'code' &&
            !(failed && f.name == 'error') &&
            !hideFields.contains(f.name))
          f,
    ];
    return SectionCard(
      title: title,
      subtitle: subtitle,
      trailing: (code != null || result is SimplePromptResult)
          ? CodeChip(code: code)
          : null,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (failed) ...[
            ErrorBanner(guidance: guidanceFor(code), rawMessage: error),
            const SizedBox(height: 8),
          ],
          for (final f in fields) ResultFieldRow(field: f),
          ...children,
        ],
      ),
    );
  }
}

/// One result field: long key/signature material in a [MonoBlock],
/// everything else in a [KeyValueRow].
class ResultFieldRow extends StatelessWidget {
  /// Creates the row.
  const ResultFieldRow({super.key, required this.field});

  /// The field.
  final ResultField field;

  @override
  Widget build(BuildContext context) {
    final long = field.value.length > 72 || field.value.contains('\n');
    if (field.monospace && long) {
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: MonoBlock(
          label: field.name,
          text: field.value,
          maxHeight: 200,
        ),
      );
    }
    return KeyValueRow(
      label: field.name,
      value: field.value,
      monospace: field.monospace,
      copyable: field.monospace,
    );
  }
}

/// Explains an `authenticationType` value for the current platform.
class AuthTypeNote extends StatelessWidget {
  /// Creates the note.
  const AuthTypeNote({super.key, required this.type, this.silentKey = false});

  /// The reported type.
  final AuthenticationType? type;

  /// Whether the key never prompts.
  final bool silentKey;

  @override
  Widget build(BuildContext context) {
    final label = describeAuthenticationType(
      type,
      platform: currentDevicePlatform(),
      silentKey: silentKey,
    );
    return Padding(
      padding: const EdgeInsets.only(top: 8),
      child: CheckRow(
        kind: StatusKind.info,
        title: 'authenticationType: ${label.label}',
        detail: label.reliability,
      ),
    );
  }
}

/// Parses a plugin public key string and shows algorithm and fingerprint.
class PublicKeySummary extends StatelessWidget {
  /// Creates the summary.
  const PublicKeySummary({super.key, required this.publicKey, this.label});

  /// The plugin's publicKey string (any format).
  final String publicKey;

  /// Which key this is.
  final String? label;

  @override
  Widget build(BuildContext context) {
    String title;
    String detail;
    StatusKind kind;
    try {
      final key = ParsedPublicKey.parse(publicKey);
      title = '${label ?? 'Public key'}: ${key.description}';
      detail = 'SubjectPublicKeyInfo DER, SHA-256 fingerprint '
          '${formatFingerprint(key.fingerprint, maxGroups: 8)}';
      kind = StatusKind.info;
    } on FormatException catch (e) {
      title = '${label ?? 'Public key'} could not be parsed';
      detail = e.message;
      kind = StatusKind.warning;
    }
    return CheckRow(kind: kind, title: title, detail: detail);
  }
}
