import 'package:examples_shared/crypto.dart';

/// Prefix of every account key alias.
const String accountAliasPrefix = 'acct_';

final RegExp _aliasPattern = RegExp(r'^[a-z0-9_-]{1,64}$');

/// A fresh key alias for one account on this device, e.g. `acct_3f9a1c02de`.
///
/// Each account gets its own key, so accounts never share a key and one
/// can be removed without touching the others. Aliases are limited to
/// `[a-z0-9_-]`: Windows stores them in settings keys and Android uses them
/// in file names.
String newAccountAlias() => '$accountAliasPrefix${toHex(secureRandomBytes(5))}';

/// Whether [alias] is safe to pass to the plugin on every platform.
bool isValidAlias(String alias) => _aliasPattern.hasMatch(alias);
