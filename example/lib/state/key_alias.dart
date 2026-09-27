import 'package:flutter/foundation.dart';

/// A key alias as passed to the plugin's `keyAlias` parameter.
///
/// The plugin cannot list the aliases that exist on a device, so the
/// Explorer works with a fixed set of [known] aliases plus one free-text
/// "probe" alias. Aliases are limited to `[a-z0-9_-]`: Windows stores them
/// in settings keys and Android uses them in file names.
@immutable
class KeyAlias {
  const KeyAlias._(this.value);

  /// The plugin's default alias (`keyAlias: null`).
  static const KeyAlias defaultAlias = KeyAlias._(null);

  /// General-purpose alias used by default on the Keys screen.
  static const KeyAlias explorerA = KeyAlias._('explorer_a');

  /// Second alias, also used by the keyInvalidated walkthrough.
  static const KeyAlias explorerB = KeyAlias._('explorer_b');

  /// Suggested alias for a non-interactive (`requireAuthentication: false`)
  /// key.
  static const KeyAlias explorerSilent = KeyAlias._('explorer_silent');

  /// Scratch alias used (and deleted again) by the error triggers.
  static const KeyAlias errorsScratch = KeyAlias._('explorer_errors');

  /// Alias that the keyNotFound trigger deletes before signing with it.
  static const KeyAlias missing = KeyAlias._('explorer_missing');

  /// The aliases every screen offers.
  static const List<KeyAlias> known = [
    defaultAlias,
    explorerA,
    explorerB,
    explorerSilent,
  ];

  static final RegExp _pattern = RegExp(r'^[a-z0-9_-]{1,64}$');

  /// Why [text] is not a valid alias, or `null` when it is.
  static String? validate(String text) {
    final trimmed = text.trim();
    if (trimmed.isEmpty) return 'Enter an alias';
    if (!_pattern.hasMatch(trimmed)) {
      return 'Use 1–64 characters from a–z, 0–9, _ and -';
    }
    return null;
  }

  /// A named alias from [text], or `null` when [text] is not valid.
  static KeyAlias? tryParse(String text) =>
      validate(text) == null ? KeyAlias._(text.trim()) : null;

  /// The value passed to the plugin (`null` = default alias).
  final String? value;

  /// Whether this is the plugin's default alias.
  bool get isDefault => value == null;

  /// Display label.
  String get label => value ?? '(default)';

  @override
  bool operator ==(Object other) => other is KeyAlias && other.value == value;

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => 'KeyAlias($label)';
}
