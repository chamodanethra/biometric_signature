import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';

import 'models.dart';
import 'policy.dart';

/// A rejection: becomes `{"ok": false, "error": code, "reason": …}`.
class _Rejection implements Exception {
  _Rejection(this.code, this.reason, {this.checks = const [], this.report});

  final String code;
  final String reason;
  final List<AttestationCheck> checks;
  final AttestationReport? report;
}

/// The outcome of checking a new key and its attestation.
class _EvaluatedKey {
  const _EvaluatedKey(this.publicKey, this.algorithm, this.report);

  final String publicKey;
  final SignatureAlgorithm algorithm;
  final AttestationReport report;
}

/// The mock relying party: registration with attestation, challenge-response
/// login, recovery and signed unbinding.
///
/// It runs in-process behind a [MockTransport], so every request and
/// response crosses a real JSON boundary. Records persist in [store];
/// challenges and sessions live in memory.
///
/// **Demo code, not production code.** A real server additionally needs
/// TLS, rate limiting, durable storage, attestation revocation checks and a
/// pinned app signing-certificate digest (see the README).
class AuthServer with Observable {
  /// Creates the server and registers its routes on [transport].
  ///
  /// [trustedRootSpkiSha256] overrides Google's attestation roots (tests
  /// trust the fake platform's synthetic root). With [verifyInIsolate],
  /// attestation chains are verified on a background isolate.
  AuthServer({
    required this.store,
    required this.transport,
    Clock? clock,
    this.trustedRootSpkiSha256,
    this.verifyInIsolate = true,
    ServerPolicy policy = const ServerPolicy(),
  })  : clock = clock ?? transport.clock,
        _policy = policy {
    challenges = ChallengeStore(clock: this.clock);
    audit = AuditLog(store: store, clock: this.clock);
    _on(ApiRoutes.registerBegin, _registerBegin);
    _on(ApiRoutes.registerFinish, _registerFinish);
    _on(ApiRoutes.loginBegin, _loginBegin);
    _on(ApiRoutes.loginFinish, _loginFinish);
    _on(ApiRoutes.recoveryBegin, _recoveryBegin);
    _on(ApiRoutes.recoveryFinish, _recoveryFinish);
    _on(ApiRoutes.deviceStatus, _deviceStatus);
    _on(ApiRoutes.unbindBegin, _unbindBegin);
    _on(ApiRoutes.unbindFinish, _unbindFinish);
    _on(ApiRoutes.logout, _logout);
  }

  /// Where users, device keys, the policy and the audit log persist.
  final KeyValueStore store;

  /// The wire this server listens on.
  final MockTransport transport;

  /// The server's clock (skewable for fault injection).
  final Clock clock;

  /// Trusted attestation roots (SPKI SHA-256); `null` = Google's roots.
  final Set<String>? trustedRootSpkiSha256;

  /// Verify attestation chains on a background isolate.
  final bool verifyInIsolate;

  /// Issued challenges and nonces (in memory, with TTL, single use).
  late final ChallengeStore challenges;

  /// Security-relevant events.
  late final AuditLog audit;

  ServerPolicy _policy;
  final Map<String, UserRecord> _users = {};
  final Map<String, DeviceKeyRecord> _devices = {};
  final Map<String, SessionRecord> _sessions = {};
  final Map<String, Duration> _clockJumps = {};

  static const String _usersKey = 'users';
  static const String _devicesKey = 'device_keys';
  static const String _policyKey = 'policy';

  /// The current policy.
  ServerPolicy get policy => _policy;

  /// Users, oldest first.
  List<UserRecord> get users => _users.values.toList()
    ..sort((a, b) => a.createdAt.compareTo(b.createdAt));

  /// Every device key record, oldest first.
  List<DeviceKeyRecord> get deviceKeys => _devices.values.toList()
    ..sort((a, b) => a.createdAt.compareTo(b.createdAt));

  /// Live sessions.
  List<SessionRecord> get sessions => _sessions.values.toList();

  /// A user by id.
  UserRecord? user(String userId) => _users[userId];

  /// A device key by id.
  DeviceKeyRecord? deviceKey(String deviceKeyId) => _devices[deviceKeyId];

  /// Clock jumps armed with [jumpClockBeforeNext], by route.
  Map<String, Duration> get pendingClockJumps => Map.unmodifiable(_clockJumps);

  /// Loads persisted records.
  Future<void> load() async {
    final policy = await store.readMap(_policyKey);
    if (policy != null) _policy = ServerPolicy.fromJson(policy);
    final users = await store.readMap(_usersKey) ?? const {};
    final devices = await store.readMap(_devicesKey) ?? const {};
    _users
      ..clear()
      ..addAll({
        for (final e in users.entries)
          e.key: UserRecord.fromJson(e.value as Map<String, dynamic>),
      });
    _devices
      ..clear()
      ..addAll({
        for (final e in devices.entries)
          e.key: DeviceKeyRecord.fromJson(e.value as Map<String, dynamic>),
      });
    await audit.load();
    notifyListeners();
  }

  /// Replaces the policy.
  Future<void> updatePolicy(ServerPolicy policy) async {
    _policy = policy;
    await store.write(_policyKey, policy.toJson());
    await audit.record('server', 'policy.changed', detail: policy.describe());
    notifyListeners();
  }

  /// Fault injection: move the server clock forward by [by] right before
  /// the next request on [route] is handled — e.g. to let a login nonce
  /// expire between `/login/begin` and `/login/finish`.
  void jumpClockBeforeNext(String route, Duration by) {
    _clockJumps[route] = by;
    notifyListeners();
  }

  /// Cancels armed clock jumps.
  void clearClockJumps() {
    _clockJumps.clear();
    notifyListeners();
  }

  /// Forgets everything: records, policy, audit log, challenges, sessions.
  Future<void> reset() async {
    await store.clear();
    _users.clear();
    _devices.clear();
    _sessions.clear();
    _clockJumps.clear();
    challenges.clear();
    _policy = const ServerPolicy();
    clock.skew = Duration.zero;
    await audit.clear();
    await audit.record('server', 'demo.reset',
        detail: 'All server records, sessions and challenges were cleared.');
    notifyListeners();
  }

  // ---------------------------------------------------------------------
  // Routing

  void _on(
    String route,
    Future<Map<String, dynamic>> Function(Map<String, dynamic> body) handler,
  ) {
    transport.register(route, (body) async {
      final jump = _clockJumps.remove(route);
      if (jump != null) {
        clock.skew += jump;
        await audit.record('server', 'fault.clock',
            detail: 'Server clock moved forward ${jump.inMinutes} min before '
                'handling $route (fault injection).',
            severity: AuditSeverity.warning);
        notifyListeners();
      }
      try {
        final response = await handler(body);
        notifyListeners();
        return {'ok': true, ...response};
      } on _Rejection catch (r) {
        await audit.record(
          _actor(body),
          '${route.substring(1).replaceAll('/', '.')}.rejected',
          detail: '${r.code}: ${r.reason}',
          severity: AuditSeverity.danger,
        );
        notifyListeners();
        return {
          'ok': false,
          'error': r.code,
          'reason': r.reason,
          if (r.checks.isNotEmpty)
            'checks': [for (final c in r.checks) c.toJson()],
          if (r.report != null) 'report': r.report!.toJson(),
        };
      }
    });
  }

  String _actor(Map<String, dynamic> body) {
    final username = body['username'];
    if (username is String && username.isNotEmpty) {
      return normalizeUsername(username);
    }
    final userId = body['userId'];
    if (userId is String) return _users[userId]?.username ?? userId;
    return 'anonymous';
  }

  static String _string(Map<String, dynamic> body, String key) {
    final value = body[key];
    if (value is String && value.isNotEmpty) return value;
    throw _Rejection(ServerErrors.badRequest, 'Missing field "$key".');
  }

  static bool _bool(Map<String, dynamic> body, String key) => body[key] == true;

  String _username(Map<String, dynamic> body) {
    final username = normalizeUsername(_string(body, 'username'));
    final problem = usernameProblem(username);
    if (problem != null) throw _Rejection(ServerErrors.badRequest, problem);
    return username;
  }

  UserRecord? _userByName(String username) {
    for (final u in _users.values) {
      if (u.username == username) return u;
    }
    return null;
  }

  List<DeviceKeyRecord> _activeDevices(String userId) => [
        for (final d in _devices.values)
          if (d.userId == userId && d.isActive) d,
      ];

  Future<void> _persist() async {
    await store.write(_usersKey, {
      for (final u in _users.values) u.userId: u.toJson(),
    });
    await store.write(_devicesKey, {
      for (final d in _devices.values) d.deviceKeyId: d.toJson(),
    });
  }

  String _cannotAttest(DevicePlatform platform) =>
      '${platform.label} has no per-key hardware attestation (only Android '
      'can prove where a key lives), and the server requires attestation. '
      'Turn off "Require attestation" in the server console to register '
      'this device with trust tier "Not attested".';

  Map<String, dynamic> _challengeResponse(IssuedChallenge c) => {
        ...c.toJson(),
        'rp': relyingPartyId,
        'attestation': _policy.requireAttestation ? 'required' : 'optional',
      };

  // ---------------------------------------------------------------------
  // Registration

  Future<Map<String, dynamic>> _registerBegin(Map<String, dynamic> body) async {
    final username = _username(body);
    if (_userByName(username) != null) {
      throw _Rejection(ServerErrors.usernameTaken,
          'The username "$username" is already registered.');
    }
    final platform = DevicePlatform.fromName(body['platform'] as String?);
    if (_policy.requireAttestation && platform != DevicePlatform.android) {
      throw _Rejection(
          ServerErrors.attestationRequired, _cannotAttest(platform));
    }
    final c = challenges.issue(
      purpose: Purposes.register,
      length: 32,
      ttl: _policy.registrationChallengeTtl,
      boundTo: username,
    );
    await audit.record(username, 'register.challenge',
        detail: 'Attestation challenge ${c.id} (declared platform '
            '${platform.label}), valid until ${c.expiresAt.toIso8601String()}.');
    return _challengeResponse(c);
  }

  Future<Map<String, dynamic>> _registerFinish(
      Map<String, dynamic> body) async {
    final username = _username(body);
    final challengeId = _string(body, 'challengeId');
    // Peek, don't consume: the device already embedded this challenge in
    // its key's attestation, so a lost upload must be retryable with the
    // same challenge until its TTL. It is consumed on success below.
    final peek = challenges.peek(challengeId,
        purpose: Purposes.register, boundTo: username);
    if (peek is! ChallengeOk) {
      throw _Rejection(ServerErrors.challenge, peek.reason);
    }
    if (_userByName(username) != null) {
      throw _Rejection(ServerErrors.usernameTaken,
          'The username "$username" is already registered.');
    }
    final key = await _evaluateKey(body, peek.challenge);

    final now = clock.now();
    final userId = 'u_${toHex(secureRandomBytes(6))}';
    final recoveryCode = generateRecoveryCode();
    final salt = toHex(secureRandomBytes(16));
    _users[userId] = UserRecord(
      userId: userId,
      username: username,
      createdAt: now,
      recoverySalt: salt,
      recoveryCodeHash: hashRecoveryCode(salt, recoveryCode),
      recoveryCodeIssuedAt: now,
    );
    final device = _newDevice(userId, body, key, now);
    challenges.markUsed(challengeId);
    await _persist();
    await audit.record(username, 'register.accepted',
        detail: '${device.alias} (${device.deviceKeyId}): '
            '${key.report.trustTier.label}, ${key.algorithm.label}. '
            '${_authTypeNote(body)}',
        severity:
            key.report.passed ? AuditSeverity.success : AuditSeverity.warning);
    return {
      'userId': userId,
      'username': username,
      'deviceKeyId': device.deviceKeyId,
      'trustTier': key.report.trustTier.name,
      'report': key.report.toJson(),
      'recoveryCode': recoveryCode,
    };
  }

  /// Checks the public key and the attestation chain of a new key.
  Future<_EvaluatedKey> _evaluateKey(
      Map<String, dynamic> body, IssuedChallenge challenge) async {
    final publicKey = _string(body, 'publicKey');
    final ParsedPublicKey parsed;
    try {
      parsed = ParsedPublicKey.parse(publicKey);
    } on FormatException catch (e) {
      throw _Rejection(
          ServerErrors.badKey, 'Malformed public key: ${e.message}');
    }
    final algorithm = switch (parsed) {
      EcPublicKeyInfo(curve: EcCurve.p256) => SignatureAlgorithm.ecdsaSha256,
      RsaPublicKeyInfo(keySizeBits: final bits) when bits >= 2048 =>
        SignatureAlgorithm.rsaPkcs1Sha256,
      _ => throw _Rejection(
          ServerErrors.badKey,
          'Only EC P-256 and RSA ≥ 2048 keys are accepted, not '
          '${parsed.description}.'),
    };
    for (final d in _devices.values) {
      if (d.isActive && d.fingerprint == parsed.fingerprint) {
        throw _Rejection(ServerErrors.keyReused,
            'This public key is already registered (${d.deviceKeyId}).');
      }
    }

    final platform = DevicePlatform.fromName(body['platform'] as String?);
    final rawChain = body['attestationChain'];
    final List<Uint8List> chain;
    try {
      chain = rawChain is List
          ? [for (final c in rawChain) base64.decode(c as String)]
          : const [];
    } on FormatException {
      throw _Rejection(
          ServerErrors.badRequest, 'attestationChain is not base64.');
    }

    if (chain.isEmpty) {
      if (_policy.requireAttestation) {
        throw _Rejection(
          ServerErrors.attestationRequired,
          platform == DevicePlatform.android
              ? 'No attestation chain was sent, and the server requires one.'
              : _cannotAttest(platform),
          report: AttestationReport.notProvided(
              'No attestation chain was sent.',
              at: clock.now()),
        );
      }
      return _EvaluatedKey(
        publicKey,
        algorithm,
        AttestationReport.notProvided(
          'The client (declared platform: ${platform.label}) sent no '
          'attestation, so the server cannot tell whether this key lives '
          'in secure hardware. Accepted as "Not attested" because '
          '"Require attestation" is off.',
          at: clock.now(),
        ),
      );
    }

    final report = await _verifyChain(chain, challenge.bytes, publicKey);
    if (!report.passed && _policy.requireAttestation) {
      throw _Rejection(
        ServerErrors.attestationFailed,
        'The key attestation did not verify: '
        '${report.failures.map((c) => c.title).join('; ')}.',
        report: report,
      );
    }
    return _EvaluatedKey(publicKey, algorithm, report);
  }

  Future<AttestationReport> _verifyChain(
      List<Uint8List> chain, Uint8List challenge, String publicKey) {
    if (verifyInIsolate) {
      return AttestationVerifier.verifyInIsolate(
        chain: chain,
        expectedChallenge: challenge,
        expectedPublicKey: publicKey,
        policy: _policy.toAttestationPolicy(),
        trustedRootSpkiSha256: trustedRootSpkiSha256,
        now: clock.now(),
      );
    }
    return Future.value(AttestationVerifier(
      trustedRootSpkiSha256: trustedRootSpkiSha256,
      now: clock.now,
    ).verify(
      chain: chain,
      expectedChallenge: challenge,
      expectedPublicKey: publicKey,
      policy: _policy.toAttestationPolicy(),
    ));
  }

  DeviceKeyRecord _newDevice(String userId, Map<String, dynamic> body,
      _EvaluatedKey key, DateTime now) {
    final alias = _string(body, 'alias');
    final device = DeviceKeyRecord(
      deviceKeyId: 'dk_${toHex(secureRandomBytes(6))}',
      userId: userId,
      alias: alias,
      publicKey: key.publicKey,
      algorithm: key.algorithm,
      platform: DevicePlatform.fromName(body['platform'] as String?).label,
      trustTier: key.report.trustTier,
      attestation: key.report.toJson(),
      createdAt: now,
      allowDeviceCredentials: _bool(body, 'allowDeviceCredentials'),
      invalidateOnEnrollment: _bool(body, 'invalidateOnEnrollment'),
      registrationAuthenticationType: body['authenticationType'] as String?,
    );
    _devices[device.deviceKeyId] = device;
    return device;
  }

  static String _authTypeNote(Map<String, dynamic> body) {
    final type = body['authenticationType'];
    return 'authenticationType=${type ?? 'not reported'} (client-reported, '
        'not signed: recorded, not trusted).';
  }

  // ---------------------------------------------------------------------
  // Login and signed requests

  Future<Map<String, dynamic>> _loginBegin(Map<String, dynamic> body) async {
    final username = _username(body);
    final user = _userByName(username);
    if (user == null) {
      throw _Rejection(ServerErrors.unknownUser, 'No account "$username".');
    }
    final active = _activeDevices(user.userId);
    if (active.isEmpty) {
      throw _Rejection(
          ServerErrors.deviceInactive,
          'No active device key for "$username". Bind this device with the '
          'recovery code.');
    }
    final c = challenges.issue(
      purpose: Purposes.login,
      length: 32,
      ttl: _policy.loginNonceTtl,
      boundTo: user.userId,
    );
    await audit.record(username, 'login.challenge',
        detail: 'Nonce ${c.id}, valid until '
            '${c.expiresAt.toIso8601String()}.');
    return {
      ..._challengeResponse(c),
      'userId': user.userId,
      'username': user.username,
      'nonce': c.base64Value,
      // Like WebAuthn's allowCredentials: which keys may answer, so a
      // reinstalled app can find a key that survived (iOS keychain).
      'devices': [
        for (final d in active)
          {
            'deviceKeyId': d.deviceKeyId,
            'alias': d.alias,
            'allowDeviceCredentials': d.allowDeviceCredentials,
            'invalidateOnEnrollment': d.invalidateOnEnrollment,
          },
      ],
    };
  }

  Future<Map<String, dynamic>> _loginFinish(Map<String, dynamic> body) async {
    final (user, device, checks) = _verifySignedChallenge(Purposes.login, body);
    final now = clock.now();
    final authType = body['authenticationType'] as String?;
    final session = SessionRecord(
      token: toHex(secureRandomBytes(24)),
      userId: user.userId,
      username: user.username,
      deviceKeyId: device.deviceKeyId,
      trustTier: device.trustTier,
      issuedAt: now,
      expiresAt: now.add(_policy.sessionTtl),
    );
    _sessions[session.token] = session;
    _devices[device.deviceKeyId] = device.copyWith(
      lastLoginAt: now,
      lastAuthenticationType: authType ?? 'not reported',
      loginCount: device.loginCount + 1,
    );
    await _persist();
    await audit.record(user.username, 'login.accepted',
        detail: '${device.alias} (${device.trustTier.label}). '
            '${_authTypeNote(body)}',
        severity: AuditSeverity.success);
    return {
      'session': session.toJson(),
      'checks': [for (final c in checks) c.toJson()],
    };
  }

  /// Verifies a signed answer to a nonce: consume first, then check the
  /// binding, the key and the signature over bytes rebuilt from the
  /// server's own record of the challenge.
  (UserRecord, DeviceKeyRecord, List<AttestationCheck>) _verifySignedChallenge(
      String purpose, Map<String, dynamic> body) {
    final checks = <AttestationCheck>[];
    Never fail(String code, String id, String title, String detail) {
      checks.add(AttestationCheck(
          id: id, title: title, status: CheckStatus.fail, detail: detail));
      throw _Rejection(code, detail, checks: checks);
    }

    final challengeId = _string(body, 'challengeId');
    final userId = _string(body, 'userId');
    // 1. Consume the nonce before anything else, so a failed or replayed
    //    attempt can never leave it usable.
    final result =
        challenges.consume(challengeId, purpose: purpose, boundTo: userId);
    if (result is! ChallengeOk) {
      fail(ServerErrors.challenge, 'nonce', 'Nonce accepted',
          '${result.reason[0].toUpperCase()}${result.reason.substring(1)}.');
    }
    final c = result.challenge;
    checks
      ..add(AttestationCheck(
        id: 'nonce',
        title: 'Nonce consumed',
        status: CheckStatus.pass,
        detail: 'Single use: nonce ${c.id} is now spent, whatever the outcome '
            '(issued ${c.issuedAt.toIso8601String()}, TTL '
            '${c.expiresAt.difference(c.issuedAt).inSeconds}s).',
      ))
      ..add(AttestationCheck(
        id: 'binding',
        title: 'Bound to this user and purpose',
        status: CheckStatus.pass,
        detail: 'Issued for userId $userId and purpose "$purpose".',
      ));

    final user = _users[userId];
    final deviceKeyId = _string(body, 'deviceKeyId');
    final device = _devices[deviceKeyId];
    if (user == null || device == null || device.userId != userId) {
      fail(ServerErrors.deviceInactive, 'device', 'Device key registered',
          'Device key $deviceKeyId is not registered to this user.');
    }
    if (!device.isActive) {
      fail(
          ServerErrors.deviceInactive,
          'device',
          'Device key active',
          'Key ${device.alias} was ${device.status.name}'
              '${device.supersededBy == null ? '' : ' by ${device.supersededBy}'}; '
              'the server no longer accepts it.');
    }
    checks.add(AttestationCheck(
      id: 'device',
      title: 'Device key active',
      status: CheckStatus.pass,
      detail: '${device.alias} · ${device.trustTier.label} · '
          '${device.algorithm.label}',
    ));

    final payload = signedChallengePayload(
      purpose: c.purpose,
      rp: relyingPartyId,
      userId: c.boundTo!,
      challengeId: c.id,
      nonceBase64: c.base64Value,
    );
    checks.add(AttestationCheck(
      id: 'payload',
      title: 'Payload rebuilt from server state',
      status: CheckStatus.info,
      detail: '${payload.length} bytes of canonical JSON built from the '
          'stored challenge (SHA-256 ${sha256Hex(payload).substring(0, 16)}…). '
          'Nothing the client sent is re-serialized.',
    ));

    final Uint8List signature;
    try {
      signature = base64.decode(_string(body, 'signature'));
    } on FormatException {
      fail(ServerErrors.badSignature, 'signature', 'Signature verifies',
          'The signature is not base64.');
    }
    final outcome = verifySignature(
      publicKey: device.publicKey,
      message: payload,
      signature: signature,
      algorithm: device.algorithm,
    );
    if (!outcome.isValid) {
      fail(
          ServerErrors.badSignature,
          'signature',
          'Signature verifies',
          '${outcome.message} (${device.algorithm.label}, key registered '
              '${device.createdAt.toIso8601String()}).');
    }
    checks
      ..add(AttestationCheck(
        id: 'signature',
        title: 'Signature verifies',
        status: CheckStatus.pass,
        detail: '${device.algorithm.label} with the public key registered '
            '${device.createdAt.toIso8601String()}.',
      ))
      ..add(AttestationCheck(
        id: 'authType',
        title: 'authenticationType: '
            '${body['authenticationType'] ?? 'not reported'}',
        status: CheckStatus.info,
        detail: 'Reported by the client and not covered by the signature, '
            'so it is recorded for audit only. What the key requires is '
            'proven by the attestation (Android), not by this field.',
      ));
    return (user, device, checks);
  }

  // ---------------------------------------------------------------------
  // Recovery

  UserRecord _checkRecoveryCode(Map<String, dynamic> body) {
    final username = _username(body);
    final user = _userByName(username);
    final code = _string(body, 'recoveryCode');
    if (user == null ||
        !constantTimeEquals(
          utf8.encode(hashRecoveryCode(user.recoverySalt, code)),
          utf8.encode(user.recoveryCodeHash),
        )) {
      throw _Rejection(ServerErrors.badRecoveryCode,
          'Unknown username or wrong recovery code.');
    }
    return user;
  }

  Future<Map<String, dynamic>> _recoveryBegin(Map<String, dynamic> body) async {
    final user = _checkRecoveryCode(body);
    final platform = DevicePlatform.fromName(body['platform'] as String?);
    if (_policy.requireAttestation && platform != DevicePlatform.android) {
      throw _Rejection(
          ServerErrors.attestationRequired, _cannotAttest(platform));
    }
    final c = challenges.issue(
      purpose: Purposes.recovery,
      length: 32,
      ttl: _policy.registrationChallengeTtl,
      boundTo: user.userId,
    );
    await audit.record(user.username, 'recovery.challenge',
        detail: 'Recovery code accepted; attestation challenge ${c.id}.',
        severity: AuditSeverity.warning);
    return {..._challengeResponse(c), 'userId': user.userId};
  }

  Future<Map<String, dynamic>> _recoveryFinish(
      Map<String, dynamic> body) async {
    final user = _checkRecoveryCode(body);
    final challengeId = _string(body, 'challengeId');
    final peek = challenges.peek(challengeId,
        purpose: Purposes.recovery, boundTo: user.userId);
    if (peek is! ChallengeOk) {
      throw _Rejection(ServerErrors.challenge, peek.reason);
    }
    final key = await _evaluateKey(body, peek.challenge);
    final now = clock.now();
    final device = _newDevice(user.userId, body, key, now);
    final superseded = <String>[];
    for (final old in _activeDevices(user.userId)) {
      if (old.deviceKeyId == device.deviceKeyId) continue;
      _devices[old.deviceKeyId] = old.copyWith(
        status: DeviceKeyStatus.superseded,
        statusChangedAt: now,
        supersededBy: device.deviceKeyId,
      );
      _sessions.removeWhere((_, s) => s.deviceKeyId == old.deviceKeyId);
      superseded.add(old.deviceKeyId);
    }
    final newCode = generateRecoveryCode();
    final salt = toHex(secureRandomBytes(16));
    _users[user.userId] = user.withRecoveryCode(
        salt: salt, hash: hashRecoveryCode(salt, newCode), issuedAt: now);
    challenges.markUsed(challengeId);
    await _persist();
    await audit.record(user.username, 'recovery.accepted',
        detail: 'New key ${device.alias} (${device.deviceKeyId}, '
            '${key.report.trustTier.label}); superseded '
            '${superseded.isEmpty ? 'nothing' : superseded.join(', ')}. '
            'Recovery code rotated.',
        severity: AuditSeverity.warning);
    return {
      'userId': user.userId,
      'username': user.username,
      'deviceKeyId': device.deviceKeyId,
      'trustTier': key.report.trustTier.name,
      'report': key.report.toJson(),
      'recoveryCode': newCode,
      'superseded': superseded,
    };
  }

  // ---------------------------------------------------------------------
  // Devices and sessions

  Future<Map<String, dynamic>> _deviceStatus(Map<String, dynamic> body) async {
    final device = _devices[_string(body, 'deviceKeyId')];
    if (device == null || device.userId != _string(body, 'userId')) {
      throw _Rejection(
          ServerErrors.deviceInactive, 'The server has no such device key.');
    }
    return {'device': device.toJson()};
  }

  Future<Map<String, dynamic>> _unbindBegin(Map<String, dynamic> body) async {
    final userId = _string(body, 'userId');
    final device = _devices[_string(body, 'deviceKeyId')];
    if (device == null || device.userId != userId || !device.isActive) {
      throw _Rejection(
          ServerErrors.deviceInactive, 'No active device key to unbind.');
    }
    final c = challenges.issue(
      purpose: Purposes.unbind,
      length: 32,
      ttl: _policy.loginNonceTtl,
      boundTo: userId,
    );
    return {..._challengeResponse(c), 'nonce': c.base64Value};
  }

  Future<Map<String, dynamic>> _unbindFinish(Map<String, dynamic> body) async {
    final (user, device, checks) =
        _verifySignedChallenge(Purposes.unbind, body);
    _devices[device.deviceKeyId] = device.copyWith(
      status: DeviceKeyStatus.unbound,
      statusChangedAt: clock.now(),
    );
    _sessions.removeWhere((_, s) => s.deviceKeyId == device.deviceKeyId);
    await _persist();
    await audit.record(user.username, 'device.unbound',
        detail: '${device.alias} (${device.deviceKeyId}) removed by a signed '
            'request.',
        severity: AuditSeverity.warning);
    return {
      'checks': [for (final c in checks) c.toJson()]
    };
  }

  Future<Map<String, dynamic>> _logout(Map<String, dynamic> body) async {
    final session = _sessions.remove(_string(body, 'token'));
    if (session != null) {
      await audit.record(session.username, 'session.ended');
    }
    return const {};
  }
}
