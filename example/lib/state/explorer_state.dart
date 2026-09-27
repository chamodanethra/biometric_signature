import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import 'call_log.dart';
import 'controllers.dart';
import 'key_alias.dart';
import 'result_fields.dart';
import 'traced_api.dart';

/// Verifies an attestation chain for display. The default runs the shared
/// [AttestationVerifier] against Google's roots on a background isolate;
/// tests inject a synchronous verifier that trusts a synthetic root.
typedef AttestationInspector = Future<AttestationReport> Function({
  required List<Uint8List> chain,
  required Uint8List expectedChallenge,
  required String expectedPublicKey,
});

/// The default [AttestationInspector].
Future<AttestationReport> inspectAttestationInIsolate({
  required List<Uint8List> chain,
  required Uint8List expectedChallenge,
  required String expectedPublicKey,
}) =>
    AttestationVerifier.verifyInIsolate(
      chain: chain,
      expectedChallenge: expectedChallenge,
      expectedPublicKey: expectedPublicKey,
    );

/// The Explorer's top-level destinations.
enum ExplorerDestination {
  /// Availability, device lock and capabilities.
  device('Device', 'Device', Icons.phone_android_outlined, Icons.phone_android),

  /// `createKeys`.
  keys('Keys', 'createKeys', Icons.key_outlined, Icons.key),

  /// `createSignature` / `createSignatureFromBytes`.
  sign('Sign', 'Sign', Icons.draw_outlined, Icons.draw),

  /// `decrypt`.
  decrypt('Decrypt', 'Decrypt', Icons.lock_open_outlined, Icons.lock_open),

  /// `getKeyInfo`, `biometricKeyExists`, `deleteKeys`, `deleteAllKeys`.
  inventory('Inventory', 'Key inventory', Icons.inventory_2_outlined,
      Icons.inventory_2),

  /// `simplePrompt`.
  prompt('Prompt', 'simplePrompt', Icons.fingerprint, Icons.fingerprint),

  /// All `BiometricError` codes and how to trigger them.
  errors('Errors', 'Error codes', Icons.error_outline, Icons.error);

  const ExplorerDestination(
      this.label, this.title, this.icon, this.selectedIcon);

  /// Navigation label.
  final String label;

  /// App bar title.
  final String title;

  /// Icon.
  final IconData icon;

  /// Icon when selected.
  final IconData selectedIcon;
}

/// A key created in this session: what `createKeys` returned and the
/// arguments it was called with.
///
/// The plugin is the source of truth (`getKeyInfo`); this record is the
/// fallback for data `getKeyInfo` cannot return, such as the attestation
/// challenge or the public key of an iOS RSA key made by an older plugin
/// version that has not been used since the upgrade.
class KeyRecord {
  /// Creates a record.
  KeyRecord({
    required this.alias,
    required this.result,
    required this.config,
    required this.keyFormat,
    required this.createdAt,
  });

  /// Alias.
  final KeyAlias alias;

  /// What createKeys returned.
  final KeyCreationResult result;

  /// The config it was called with.
  final CreateKeysConfig config;

  /// The key format requested.
  final KeyFormat keyFormat;

  /// When it was created.
  final DateTime createdAt;

  /// The attestation challenge sent (Android), if any.
  Uint8List? get attestationChallenge => config.attestationChallenge;

  /// Whether the key never prompts (`requireAuthentication: false`).
  bool get isSilent => config.requireAuthentication == false;
}

/// Session state shared by every screen.
///
/// Holds the call log, the traced API, the alias selection, the keys
/// created in this session and one controller per screen (so results
/// survive navigation).
class ExplorerState extends ChangeNotifier {
  /// Creates the state. [api] defaults to [BiometricSignature]; the
  /// [attestationInspector] defaults to [inspectAttestationInIsolate].
  ExplorerState({
    BiometricSignature? api,
    AttestationInspector? attestationInspector,
  })  : log = CallLog(),
        inspectAttestation =
            attestationInspector ?? inspectAttestationInIsolate {
    this.api = TracedApi(api ?? BiometricSignature(), log);
    probeAliasText.addListener(_onProbeChanged);
    device = DeviceController(this);
    keys = KeysController(this);
    sign = SignController(this);
    decrypt = DecryptController(this);
    inventory = InventoryController(this);
    prompt = PromptController(this);
    errors = ErrorsController(this);
  }

  /// Every plugin call made in this session.
  final CallLog log;

  /// The plugin, with every call recorded in [log].
  late final TracedApi api;

  /// Verifies attestation chains for display.
  final AttestationInspector inspectAttestation;

  /// Device screen.
  late final DeviceController device;

  /// Keys screen.
  late final KeysController keys;

  /// Sign screen.
  late final SignController sign;

  /// Decrypt screen.
  late final DecryptController decrypt;

  /// Inventory screen.
  late final InventoryController inventory;

  /// Prompt screen.
  late final PromptController prompt;

  /// Errors screen.
  late final ErrorsController errors;

  /// The platform the Explorer runs on.
  DevicePlatform get platform => currentDevicePlatform();

  /// What the plugin can do on [platform].
  PlatformCapabilities get capabilities => PlatformCapabilities.of(platform);

  ExplorerDestination _destination = ExplorerDestination.device;

  /// The visible destination.
  ExplorerDestination get destination => _destination;

  /// Shows [destination].
  void goTo(ExplorerDestination destination) {
    if (_destination == destination) return;
    _destination = destination;
    notifyListeners();
  }

  KeyAlias _selectedAlias = KeyAlias.explorerA;

  /// The alias the Keys, Sign and Decrypt screens act on.
  KeyAlias get selectedAlias => _selectedAlias;

  /// Selects [alias] on every screen.
  void selectAlias(KeyAlias alias) {
    if (_selectedAlias == alias) return;
    _selectedAlias = alias;
    notifyListeners();
  }

  /// Free-text "probe" alias, for keys created outside the known aliases.
  final TextEditingController probeAliasText = TextEditingController();

  KeyAlias? _probeAlias;

  /// The probe alias when [probeAliasText] is valid.
  KeyAlias? get probeAlias => _probeAlias;

  /// Validation error for a non-empty [probeAliasText].
  String? get probeAliasError => probeAliasText.text.trim().isEmpty
      ? null
      : KeyAlias.validate(probeAliasText.text);

  void _onProbeChanged() {
    final previous = _probeAlias;
    final next = KeyAlias.tryParse(probeAliasText.text);
    if (previous == next) {
      notifyListeners();
      return;
    }
    _probeAlias = next;
    final wasSelected = previous != null &&
        _selectedAlias == previous &&
        !KeyAlias.known.contains(previous);
    if (wasSelected) _selectedAlias = next ?? KeyAlias.explorerA;
    notifyListeners();
  }

  /// Known aliases plus the probe alias (when valid and not already known).
  List<KeyAlias> get aliasOptions => [
        ...KeyAlias.known,
        if (_probeAlias != null && !KeyAlias.known.contains(_probeAlias))
          _probeAlias!,
      ];

  final Map<KeyAlias, KeyRecord> _records = {};

  /// The key created under [alias] in this session, if any.
  KeyRecord? recordFor(KeyAlias alias) => _records[alias];

  /// Updates the session records after a `createKeys` call.
  ///
  /// A success replaces the record. Failures that happen before the plugin
  /// touches existing keys (keyAlreadyExists, invalidInput, and
  /// notSupported for attestation outside Android) keep it; any other
  /// failure may have deleted the old key, so the record is dropped.
  void noteCreateKeysResult({
    required KeyAlias alias,
    required KeyCreationResult result,
    required CreateKeysConfig config,
    required KeyFormat keyFormat,
  }) {
    final code = result.code;
    if (isSuccessCode(code) && result.publicKey != null) {
      _records[alias] = KeyRecord(
        alias: alias,
        result: result,
        config: config,
        keyFormat: keyFormat,
        createdAt: DateTime.now(),
      );
    } else {
      final keepsExisting = code == BiometricError.keyAlreadyExists ||
          code == BiometricError.invalidInput ||
          (code == BiometricError.notSupported &&
              platform != DevicePlatform.android);
      if (!keepsExisting) _records.remove(alias);
    }
    notifyListeners();
  }

  /// Forgets the record for [alias] (after `deleteKeys`).
  void forget(KeyAlias alias) {
    if (_records.remove(alias) != null) notifyListeners();
  }

  /// Forgets every record (after `deleteAllKeys`).
  void forgetAll() {
    _records.clear();
    notifyListeners();
  }

  @override
  void dispose() {
    for (final c in <ChangeNotifier>[
      device,
      keys,
      sign,
      decrypt,
      inventory,
      prompt,
      errors,
    ]) {
      c.dispose();
    }
    probeAliasText.dispose();
    log.dispose();
    super.dispose();
  }
}

/// Makes the [ExplorerState] available to the widget tree.
class ExplorerScope extends InheritedWidget {
  /// Creates the scope.
  const ExplorerScope({super.key, required this.state, required super.child});

  /// The state.
  final ExplorerState state;

  /// The nearest state. Widgets rebuild on changes through
  /// `ListenableBuilder`, not through this lookup.
  static ExplorerState of(BuildContext context) {
    final scope = context.getInheritedWidgetOfExactType<ExplorerScope>();
    assert(scope != null, 'No ExplorerScope above this widget');
    return scope!.state;
  }

  @override
  bool updateShouldNotify(ExplorerScope oldWidget) => state != oldWidget.state;
}
