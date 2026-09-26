import 'package:biometric_signature/biometric_signature.dart';

import 'controller_base.dart';
import 'key_alias.dart';

/// Inventory screen: `getKeyInfo`, `biometricKeyExists`, `deleteKeys` and
/// `deleteAllKeys` over the known aliases plus the probe alias.
class InventoryController extends ExplorerController {
  /// Creates the controller.
  InventoryController(super.state);

  /// Operation id for [refreshAll].
  static const String refreshAllOp = 'refreshAll';

  /// Operation id for [deleteAll].
  static const String deleteAllOp = 'deleteAll';

  /// Operation id for [refresh] of [alias].
  static String infoOp(KeyAlias alias) => 'info:${alias.label}';

  /// Operation id for [checkExists] of [alias].
  static String existsOp(KeyAlias alias) => 'exists:${alias.label}';

  /// Operation id for [delete] of [alias].
  static String deleteOp(KeyAlias alias) => 'delete:${alias.label}';

  /// `getKeyInfo(checkValidity:)` and `biometricKeyExists(checkValidity:)`.
  bool checkValidity = true;

  /// `getKeyInfo(keyFormat:)`.
  KeyFormat keyFormat = KeyFormat.base64;

  /// Last `getKeyInfo` per alias.
  final Map<KeyAlias, KeyInfo> infos = {};

  /// Last `biometricKeyExists` per alias, with the checkValidity used.
  final Map<KeyAlias, (bool exists, bool checkedValidity)> existsResults = {};

  /// Last `deleteKeys` per alias.
  final Map<KeyAlias, bool> deleteResults = {};

  /// Last `deleteAllKeys` result.
  bool? deleteAllResult;

  /// Calls `getKeyInfo` for every alias.
  Future<void> refreshAll() => run(refreshAllOp, () async {
        for (final alias in state.aliasOptions) {
          await _info(alias);
        }
      });

  /// Calls `getKeyInfo` for [alias].
  Future<void> refresh(KeyAlias alias) => run(infoOp(alias), () async {
        await _info(alias);
      });

  Future<void> _info(KeyAlias alias) async {
    infos[alias] = await api.getKeyInfo(
      keyAlias: alias.value,
      checkValidity: checkValidity,
      keyFormat: keyFormat,
    );
    notifyListeners();
  }

  /// Calls `biometricKeyExists` for [alias].
  Future<void> checkExists(KeyAlias alias) => run(existsOp(alias), () async {
        final checked = checkValidity;
        final exists = await api.biometricKeyExists(
          keyAlias: alias.value,
          checkValidity: checked,
        );
        existsResults[alias] = (exists, checked);
      });

  /// Calls `deleteKeys` for [alias].
  Future<void> delete(KeyAlias alias) => run(deleteOp(alias), () async {
        deleteResults[alias] = await api.deleteKeys(keyAlias: alias.value);
        infos.remove(alias);
        existsResults.remove(alias);
        state.forget(alias);
      });

  /// Calls `deleteAllKeys`.
  Future<void> deleteAll() => run(deleteAllOp, () async {
        deleteAllResult = await api.deleteAllKeys();
        infos.clear();
        existsResults.clear();
        deleteResults.clear();
        state.forgetAll();
      });
}
