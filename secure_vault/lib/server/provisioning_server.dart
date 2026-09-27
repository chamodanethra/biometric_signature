import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';

import '../models/sealed_item.dart';
import 'in_transit_tamper.dart';

/// A device's vault key as the provisioning server recorded it.
class RegisteredDevice {
  /// Creates a record.
  const RegisteredDevice({
    required this.deviceId,
    required this.platform,
    required this.algorithm,
    required this.keySize,
    required this.isHybridMode,
    required this.publicKey,
    required this.decryptingPublicKey,
    required this.scheme,
    required this.generation,
    required this.registeredAt,
  });

  /// Restores a record from [toJson].
  factory RegisteredDevice.fromJson(Map<String, dynamic> json) =>
      RegisteredDevice(
        deviceId: json['deviceId'] as String,
        platform: DevicePlatform.fromName(json['platform'] as String?),
        algorithm: json['algorithm'] as String? ?? '',
        keySize: json['keySize'] as int?,
        isHybridMode: json['isHybridMode'] as bool? ?? false,
        publicKey: json['publicKey'] as String?,
        decryptingPublicKey: json['decryptingPublicKey'] as String?,
        scheme: EncryptionScheme.fromJson(
            (json['scheme'] as Map).cast<String, dynamic>()),
        generation: json['generation'] as int? ?? 1,
        registeredAt: DateTime.parse(json['registeredAt'] as String),
      );

  /// Device id.
  final String deviceId;

  /// Platform the device reported.
  final DevicePlatform platform;

  /// Signing key algorithm.
  final String algorithm;

  /// Signing key size.
  final int? keySize;

  /// Android hybrid mode.
  final bool isHybridMode;

  /// Signing public key (base64 SPKI).
  final String? publicKey;

  /// Android hybrid decryption key (base64 SPKI).
  final String? decryptingPublicKey;

  /// The scheme the server seals with, resolved at registration.
  final EncryptionScheme scheme;

  /// 1 for the first key, +1 for each re-provisioning.
  final int generation;

  /// Registration time.
  final DateTime registeredAt;

  /// Fingerprint of the key the server seals to.
  String get keyFingerprint => schemeKeyFingerprint(scheme) ?? '';

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'deviceId': deviceId,
        'platform': platform.name,
        'algorithm': algorithm,
        'keySize': keySize,
        'isHybridMode': isHybridMode,
        'publicKey': publicKey,
        'decryptingPublicKey': decryptingPublicKey,
        'scheme': scheme.toJson(),
        'generation': generation,
        'registeredAt': registeredAt.toUtc().toIso8601String(),
      };
}

/// A secret the server provisions to devices.
///
/// The demo server keeps the plaintext so it can seal it again for a new
/// key. A real one would keep it in a KMS / HSM and log every seal.
class ServerSecret {
  /// Creates a secret.
  const ServerSecret({
    required this.id,
    required this.title,
    required this.value,
    required this.createdAt,
  });

  /// Restores a secret from [toJson].
  factory ServerSecret.fromJson(Map<String, dynamic> json) => ServerSecret(
        id: json['id'] as String,
        title: json['title'] as String,
        value: json['value'] as String,
        createdAt: DateTime.parse(json['createdAt'] as String),
      );

  /// Identifier.
  final String id;

  /// Title.
  final String title;

  /// Plaintext (server side only).
  final String value;

  /// When it was added.
  final DateTime createdAt;

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'id': id,
        'title': title,
        'value': value,
        'createdAt': createdAt.toUtc().toIso8601String(),
      };
}

/// The in-process "provisioning server".
///
/// - `/vault/register` records a device's vault public key and resolves the
///   encryption scheme from the platform and key (never from a UI toggle).
/// - `/vault/sync` seals every server secret to that scheme and returns
///   ciphertext only.
///
/// Demo code: registration is not authenticated. A real server must bind
/// the key to an authenticated account (for example with the attested
/// device binding shown in the passwordless_login example), use TLS, and
/// store secrets in a KMS / HSM.
class ProvisioningServer with Observable {
  /// Creates the server and registers nothing yet; call [start].
  ProvisioningServer({
    required this.transport,
    required this.store,
    InTransitTamper? tamper,
    Clock? clock,
  })  : clock = clock ?? Clock(),
        tamper = tamper ?? InTransitTamper(),
        audit = AuditLog(store: store, clock: clock);

  /// Registration route.
  static const String registerRoute = '/vault/register';

  /// Delivery route.
  static const String syncRoute = '/vault/sync';

  static const String _devicesKey = 'devices';
  static const String _secretsKey = 'secrets';

  /// The "network".
  final MockTransport transport;

  /// Persistence (`server.` prefix in the app).
  final KeyValueStore store;

  /// Simulated attacker between server and device.
  final InTransitTamper tamper;

  /// Time source.
  final Clock clock;

  /// Server audit log.
  final AuditLog audit;

  bool _started = false;

  /// Loads state, seeds the demo secrets and registers the routes.
  Future<void> start() async {
    if (_started) return;
    _started = true;
    await audit.load();
    await _seedIfEmpty();
    transport.register(registerRoute, _register);
    transport.register(syncRoute, tamper.wrap(_sync));
  }

  /// Registered devices.
  Future<List<RegisteredDevice>> devices() async =>
      (await _loadDevices()).values.toList();

  /// Secrets the server provisions.
  Future<List<ServerSecret>> secrets() async {
    final list = await store.readList(_secretsKey) ?? const <dynamic>[];
    return [
      for (final e in list)
        ServerSecret.fromJson((e as Map).cast<String, dynamic>()),
    ];
  }

  /// Adds a secret; devices receive it on their next sync.
  Future<void> addSecret(String title, String value) async {
    final list = await secrets();
    list.add(ServerSecret(
      id: toHex(secureRandomBytes(6)),
      title: title,
      value: value,
      createdAt: clock.now(),
    ));
    await store.write(_secretsKey, [for (final s in list) s.toJson()]);
    await audit.record('operator', 'secret.added',
        detail: '"$title" (${value.length} chars). Devices get it on their '
            'next sync.');
    notifyListeners();
  }

  /// Forgets every device, the audit log and the secrets, then re-seeds.
  Future<void> reset() async {
    await store.clear();
    await audit.clear();
    await _seedIfEmpty();
    notifyListeners();
  }

  Future<void> _seedIfEmpty() async {
    if (await store.read(_secretsKey) != null) return;
    final now = clock.now();
    String group() => toHex(secureRandomBytes(2));
    final codes = [
      for (var i = 0; i < 16; i++) '${group()}-${group()}-${group()}',
    ];
    final seeded = [
      ServerSecret(
        id: 'wifi',
        title: 'Office Wi-Fi password',
        value: 'violet-harbor-42-lantern',
        createdAt: now,
      ),
      ServerSecret(
        id: 'api-token',
        title: 'Staging API token',
        value: 'demo_token_${toHex(secureRandomBytes(16))}',
        createdAt: now,
      ),
      ServerSecret(
        id: 'recovery-codes',
        title: 'Account recovery codes',
        value: codes.join('\n'),
        createdAt: now,
      ),
    ];
    await store.write(_secretsKey, [for (final s in seeded) s.toJson()]);
    await audit.record('server', 'secrets.seeded',
        detail: '${seeded.length} demo secrets. The server holds their '
            'plaintext; devices only ever receive ciphertext.');
  }

  Future<Map<String, RegisteredDevice>> _loadDevices() async {
    final map = await store.readMap(_devicesKey) ?? const <String, dynamic>{};
    return {
      for (final e in map.entries)
        e.key:
            RegisteredDevice.fromJson((e.value as Map).cast<String, dynamic>()),
    };
  }

  Future<void> _saveDevices(Map<String, RegisteredDevice> devices) =>
      store.write(_devicesKey, {
        for (final e in devices.entries) e.key: e.value.toJson(),
      });

  Map<String, dynamic> _reject(String error, String reason) =>
      {'ok': false, 'error': error, 'reason': reason};

  Future<Map<String, dynamic>> _register(Map<String, dynamic> body) async {
    final deviceId = body['deviceId'];
    if (deviceId is! String || deviceId.isEmpty) {
      return _reject('bad_request', 'deviceId is required.');
    }
    final platform = DevicePlatform.fromName(body['platform'] as String?);
    final scheme = EncryptionTarget.resolve(
      platform: platform,
      algorithm: body['algorithm'] as String?,
      publicKey: body['publicKey'] as String?,
      decryptingPublicKey: body['decryptingPublicKey'] as String?,
      decryptingAlgorithm: body['decryptingAlgorithm'] as String?,
      isHybridMode: body['isHybridMode'] as bool?,
    );
    if (scheme is UnsupportedScheme) {
      await audit.record(deviceId, 'vault.register.rejected',
          detail: '${platform.label}: ${scheme.reason}',
          severity: AuditSeverity.warning);
      return _reject('unsupported_key', scheme.reason);
    }
    final devices = await _loadDevices();
    final previous = devices[deviceId];
    final device = RegisteredDevice(
      deviceId: deviceId,
      platform: platform,
      algorithm: body['algorithm'] as String? ?? '',
      keySize: body['keySize'] as int?,
      isHybridMode: body['isHybridMode'] as bool? ?? false,
      publicKey: body['publicKey'] as String?,
      decryptingPublicKey: body['decryptingPublicKey'] as String?,
      scheme: scheme,
      generation: (previous?.generation ?? 0) + 1,
      registeredAt: clock.now(),
    );
    devices[deviceId] = device;
    await _saveDevices(devices);
    final fingerprint = shortFingerprint(device.keyFingerprint);
    await audit.record(
      deviceId,
      previous == null ? 'vault.registered' : 'vault.reprovisioned',
      detail: previous == null
          ? '${platform.label}, ${scheme.label}, key $fingerprint'
          : 'Generation ${device.generation}: ${scheme.label}, key '
              '$fingerprint replaces ${shortFingerprint(previous.keyFingerprint)}. '
              'Anything sealed to the old key stays unreadable.',
      severity: AuditSeverity.success,
    );
    notifyListeners();
    return {
      'ok': true,
      'generation': device.generation,
      'keyFingerprint': device.keyFingerprint,
      'scheme': scheme.toJson(),
      'schemeLabel': scheme.label,
      'schemeDescription': scheme.description,
    };
  }

  Future<Map<String, dynamic>> _sync(Map<String, dynamic> body) async {
    final deviceId = body['deviceId'];
    if (deviceId is! String) {
      return _reject('bad_request', 'deviceId is required.');
    }
    final device = (await _loadDevices())[deviceId];
    if (device == null) {
      await audit.record(deviceId, 'vault.sync.rejected',
          detail: 'Unknown device.', severity: AuditSeverity.warning);
      return _reject('not_registered', 'This device is not registered.');
    }
    if (body['keyFingerprint'] != device.keyFingerprint) {
      await audit.record(deviceId, 'vault.sync.rejected',
          detail: 'Device presented a different key than the registered '
              '${shortFingerprint(device.keyFingerprint)}.',
          severity: AuditSeverity.warning);
      return _reject(
          'key_mismatch',
          'The server has a different vault key registered for this device. '
              'Register again.');
    }
    final items = [
      for (final secret in await secrets())
        SealedItem.seal(
          id: 'server-${secret.id}',
          title: secret.title,
          origin: ItemOrigin.server,
          scheme: device.scheme,
          plaintext: secret.value,
          createdAt: secret.createdAt,
        ),
    ];
    final envelopes =
        items.where((i) => i.format == SealFormat.envelope).length;
    await audit.record(deviceId, 'secrets.sealed',
        detail: '${items.length} items with ${device.scheme.label} '
            '(${items.length - envelopes} direct, $envelopes envelope) to key '
            '${shortFingerprint(device.keyFingerprint)}.',
        severity: AuditSeverity.success);
    return {
      'ok': true,
      'generation': device.generation,
      'items': [for (final i in items) i.toJson()],
    };
  }
}
