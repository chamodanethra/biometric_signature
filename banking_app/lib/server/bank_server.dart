/// The in-process mock bank. Demo code, not production code: it has no TLS,
/// no rate limits, simulated SMS codes, and it does not check attestation
/// certificate revocation.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';

import '../money.dart';
import 'ledger.dart';
import 'models.dart';
import 'request_signing.dart';
import 'risk_policy.dart';

/// A one-time code "sent" to the customer's phone. The app shows these in a
/// simulated SMS card; a real bank would use a separate channel.
class SimulatedSms {
  /// Creates a message.
  const SimulatedSms({
    required this.to,
    required this.text,
    required this.code,
    required this.subject,
    required this.sentAt,
  });

  /// Masked phone number.
  final String to;

  /// Message text.
  final String text;

  /// The code.
  final String code;

  /// Enrollment or re-verification id the code belongs to.
  final String subject;

  /// Send time.
  final DateTime sentAt;
}

/// Messages "sent" by the bank.
class SmsOutbox with Observable {
  final List<SimulatedSms> _messages = [];

  /// Messages, oldest first.
  List<SimulatedSms> get messages => List.unmodifiable(_messages);

  /// The newest message for [subject], if any.
  SimulatedSms? latestFor(String subject) {
    for (final m in _messages.reversed) {
      if (m.subject == subject) return m;
    }
    return null;
  }

  /// Adds a message.
  void add(SimulatedSms message) {
    _messages.add(message);
    notifyListeners();
  }

  /// Removes every message.
  void clear() {
    _messages.clear();
    notifyListeners();
  }
}

class _Otp {
  _Otp(this.code, this.expiresAt);

  final String code;
  final DateTime expiresAt;
  int attemptsLeft = 3;
}

class _PendingEnrollment {
  _PendingEnrollment({
    required this.id,
    required this.platform,
    required this.deviceChallengeId,
    required this.approvalChallengeId,
    this.previousDeviceId,
  });

  final String id;
  final DevicePlatform platform;
  final String deviceChallengeId;
  final String approvalChallengeId;
  final String? previousDeviceId;
}

class _PendingReverify {
  _PendingReverify(this.id, this.deviceId, this.challengeId, this.reason);

  final String id;
  final String deviceId;
  final String challengeId;
  final String reason;
}

/// A transfer payload issued by `/transfers/prepare`, awaiting approval.
class PendingTransfer {
  PendingTransfer._({
    required this.txnId,
    required this.deviceId,
    required this.bytes,
    required this.tier,
    required this.amountCents,
    required this.fromAccount,
    required this.payee,
    required this.issuedAt,
    required this.expiresAt,
  });

  /// Transaction id.
  final String txnId;

  /// Device it was issued to.
  final String deviceId;

  /// The exact canonical JSON bytes issued. Only these are ever verified.
  final Uint8List bytes;

  /// Risk tier decided at prepare time.
  final RiskTier tier;

  /// Amount.
  final int amountCents;

  /// Debit account.
  final String fromAccount;

  /// Payee.
  final Payee payee;

  /// Issue time.
  final DateTime issuedAt;

  /// Approval deadline.
  final DateTime expiresAt;

  /// Whether a confirmation consumed the nonce.
  bool used = false;
}

class _Ctx {
  const _Ctx(this.auth, this.device);

  final RequestAuth auth;
  final DeviceRecord? device;
}

typedef _SignedHandler = Future<Map<String, dynamic>> Function(
    Map<String, dynamic> body, _Ctx ctx);

/// The mock bank: enrollment, request verification, risk tiers, transfer
/// approval and key rotation, registered as routes on a [MockTransport].
class BankServer with Observable {
  /// Creates the server and registers its routes on [transport].
  ///
  /// [trustedRootSpkiSha256] defaults to Google's attestation roots (tests
  /// pass the fake platform's synthetic root). Attestation chains are
  /// verified on a background isolate unless [verifyAttestationInIsolate]
  /// is `false` (widget tests run in a fake-async zone).
  BankServer({
    required this.transport,
    required this.store,
    required this.clock,
    this.trustedRootSpkiSha256,
    this.verifyAttestationInIsolate = true,
    AttestationPolicy? attestationPolicy,
  })  : attestationPolicy = attestationPolicy ??
            const AttestationPolicy(expectedPackageName: androidPackageName),
        audit = AuditLog(store: store, clock: clock),
        challenges = ChallengeStore(clock: clock),
        requests = RequestVerifier(clock: clock),
        ledger = Ledger(store: store, clock: clock) {
    _registerRoutes();
  }

  /// The Android applicationId the attestation must name.
  static const String androidPackageName = 'com.example.banking_app_example';

  /// The (mock) network.
  final MockTransport transport;

  /// Server-side persistence.
  final KeyValueStore store;

  /// The bank's clock.
  final Clock clock;

  /// Trusted attestation roots (SPKI SHA-256), or `null` for Google's.
  final Set<String>? trustedRootSpkiSha256;

  /// Verify attestation chains with `Isolate.run`.
  final bool verifyAttestationInIsolate;

  /// Attestation policy (expected package name).
  final AttestationPolicy attestationPolicy;

  /// Audit trail.
  final AuditLog audit;

  /// Attestation challenges (single-use, TTL).
  final ChallengeStore challenges;

  /// Request-signature verification.
  final RequestVerifier requests;

  /// Accounts and postings.
  final Ledger ledger;

  /// Simulated SMS messages.
  final SmsOutbox outbox = SmsOutbox();

  final Random _random = Random.secure();
  RiskPolicy _policy = const RiskPolicy();
  final Map<String, DeviceRecord> _devices = {};
  final List<TransferRecord> _transfers = [];
  final Map<String, PendingTransfer> _pending = {};
  final Map<String, _PendingEnrollment> _enrollments = {};
  final Map<String, _PendingReverify> _reverifications = {};
  final Map<String, _Otp> _otps = {};

  /// The current risk policy.
  RiskPolicy get policy => _policy;

  /// Every device record.
  List<DeviceRecord> get devices => List.unmodifiable(_devices.values);

  /// The device [id], if known.
  DeviceRecord? device(String id) => _devices[id];

  /// Decided transfers, oldest first.
  List<TransferRecord> get transfers => List.unmodifiable(_transfers);

  /// Issued payloads that can still be approved.
  List<PendingTransfer> get pendingTransfers {
    final now = clock.now();
    return [
      for (final p in _pending.values)
        if (!p.used && now.isBefore(p.expiresAt)) p,
    ];
  }

  /// Loads persisted state (seeding the ledger on first run).
  Future<void> load() async {
    await ledger.load();
    await audit.load();
    final policy = await store.readMap('policy');
    if (policy != null) _policy = RiskPolicy.fromJson(policy);
    requests.maxSkew = Duration(seconds: _policy.maxClockSkewSeconds);
    _devices.clear();
    final devices = await store.readMap('devices');
    devices?.forEach((id, json) {
      _devices[id] = DeviceRecord.fromJson(json as Map<String, dynamic>);
    });
    _transfers
      ..clear()
      ..addAll([
        for (final t in await store.readList('transfers') ?? const <dynamic>[])
          TransferRecord.fromJson(t as Map<String, dynamic>),
      ]);
    notifyListeners();
  }

  /// Forgets every device, transfer and challenge and reseeds the books.
  Future<void> reset() async {
    await store.clear();
    _devices.clear();
    _transfers.clear();
    _pending.clear();
    _enrollments.clear();
    _reverifications.clear();
    _otps.clear();
    challenges.clear();
    requests.replayCache.clear();
    outbox.clear();
    _policy = const RiskPolicy();
    requests.maxSkew = Duration(seconds: _policy.maxClockSkewSeconds);
    await audit.clear();
    await ledger.reseed();
    await audit.record('server', 'demo.reset',
        detail: 'Books reseeded; device records, keys and policy reset.');
    notifyListeners();
  }

  /// Replaces the risk policy (server console).
  Future<void> updatePolicy(RiskPolicy policy) async {
    _policy = policy;
    requests.maxSkew = Duration(seconds: policy.maxClockSkewSeconds);
    await store.write('policy', policy.toJson());
    await audit.record('admin', 'policy.updated',
        detail: 'A ${policy.rangeFor(RiskTier.a)}, B '
            '${policy.rangeFor(RiskTier.b)}, tier C needs attested '
            'biometric-only: ${policy.requireAttestedBiometricOnlyForTierC}, '
            'skew ±${policy.maxClockSkewSeconds} s, approval TTL '
            '${policy.approvalTtlSeconds} s.',
        severity: AuditSeverity.warning);
    notifyListeners();
  }

  // ---------------------------------------------------------------- routes

  void _registerRoutes() {
    transport.register(BankRoutes.enrollBegin.path, _enrollBegin);
    _signed(BankRoutes.enrollFinish, _enrollFinish);
    _signed(BankRoutes.accounts, _accounts);
    _signed(BankRoutes.prepare, _prepare);
    _signed(BankRoutes.confirm, _confirm);
    _signed(BankRoutes.reverifyBegin, _reverifyBegin);
    _signed(BankRoutes.reverifyFinish, _reverifyFinish);
    _signed(BankRoutes.unbind, _unbind);
  }

  /// Registers a route whose envelope must carry a valid `device_binding`
  /// request signature. The handler only runs for authentic, fresh requests.
  void _signed(BankRoute route, _SignedHandler handler) {
    transport.register(route.path, (envelope) async {
      final auth = RequestAuth.tryParse(envelope['auth']);
      final body = envelope['body'];
      String? publicKey;
      String? problem;
      DeviceRecord? device;
      if (route.auth == RouteAuth.selfSigned) {
        final key = body is Map<String, dynamic> ? body['deviceKey'] : null;
        final pk = key is Map<String, dynamic> ? key['publicKey'] : null;
        publicKey = pk is String ? pk : null;
        problem = 'The enrollment carries no device_binding public key.';
      } else {
        final id = auth?.deviceId;
        device = id == null ? null : _devices[id];
        if (device == null) {
          problem = 'Unknown device ${id ?? '(none)'}: not bound to this bank.';
        } else if (!device.isActive) {
          problem = 'Device ${device.deviceId} is ${device.status.name}.';
        } else if (auth!.keyAlias != KeyAliases.deviceBinding) {
          problem = 'Requests must be signed with ${KeyAliases.deviceBinding}, '
              'not ${auth.keyAlias}.';
        } else {
          publicKey = device.deviceKey.publicKey;
        }
      }
      final verification = requests.verify(
        route: route,
        envelope: envelope,
        publicKey: publicKey,
        keyProblem: problem,
      );
      final requestChecks = [for (final c in verification.checks) c.toJson()];
      if (!verification.ok) {
        await audit.record(
          auth?.deviceId ?? 'unknown device',
          'request.rejected',
          detail: '$route — ${verification.reason}',
          severity: AuditSeverity.danger,
        );
        notifyListeners();
        return {
          'ok': false,
          'requestOk': false,
          'rejection': verification.rejection!.name,
          'reason': verification.reason,
          'requestChecks': requestChecks,
        };
      }
      final response =
          await handler(body as Map<String, dynamic>, _Ctx(auth!, device));
      return {...response, 'requestOk': true, 'requestChecks': requestChecks};
    });
  }

  // ------------------------------------------------------------ enrollment

  Future<Map<String, dynamic>> _enrollBegin(Map<String, dynamic> body) async {
    if (body['customerId'] != DemoCustomer.id) {
      return _reject('Unknown customer.');
    }
    final platform = DevicePlatform.fromName(body['platform'] as String?);
    final id = 'enr-${toHex(secureRandomBytes(6))}';
    const ttl = Duration(minutes: 10);
    final deviceChallenge = challenges.issue(
        purpose: 'attest:${KeyAliases.deviceBinding}', boundTo: id, ttl: ttl);
    final approvalChallenge = challenges.issue(
        purpose: 'attest:${KeyAliases.approval}', boundTo: id, ttl: ttl);
    _enrollments[id] = _PendingEnrollment(
      id: id,
      platform: platform,
      deviceChallengeId: deviceChallenge.id,
      approvalChallengeId: approvalChallenge.id,
      previousDeviceId: body['previousDeviceId'] as String?,
    );
    _sendOtp(
        id,
        'Step-up Bank: {code} is your code to bind a new device. '
        'We will never ask you for it.');
    await audit.record(DemoCustomer.id, 'enroll.begin',
        detail: '$id from ${platform.label}; one-time code sent to '
            '${DemoCustomer.phone}; two attestation challenges issued.');
    return {
      'ok': true,
      'enrollmentId': id,
      'customerName': DemoCustomer.name,
      'otpSentTo': DemoCustomer.phone,
      'attestationChallenges': {
        KeyAliases.deviceBinding: deviceChallenge.base64Value,
        KeyAliases.approval: approvalChallenge.base64Value,
      },
    };
  }

  Future<Map<String, dynamic>> _enrollFinish(
      Map<String, dynamic> body, _Ctx ctx) async {
    final id = body['enrollmentId'];
    final enrollment = id is String ? _enrollments[id] : null;
    if (enrollment == null) {
      return _reject('Unknown or expired enrollment: start again.');
    }
    final checks = <ServerCheck>[_checkOtp(enrollment.id, body['otp'])];
    if (checks.last.failed) {
      await audit.record(DemoCustomer.id, 'enroll.otp_failed',
          detail: checks.last.detail, severity: AuditSeverity.warning);
      return _reject(checks.last.detail, code: 'otp', checks: checks);
    }
    final (deviceKey, deviceCheck) = await _registerKey(
      alias: KeyAliases.deviceBinding,
      json: body['deviceKey'],
      challengeId: enrollment.deviceChallengeId,
      boundTo: enrollment.id,
      platform: enrollment.platform,
    );
    final (approvalKey, approvalCheck) = await _registerKey(
      alias: KeyAliases.approval,
      json: body['approvalKey'],
      challengeId: enrollment.approvalChallengeId,
      boundTo: enrollment.id,
      platform: enrollment.platform,
    );
    checks
      ..add(deviceCheck)
      ..add(approvalCheck);
    if (deviceKey == null || approvalKey == null) {
      return _reject('Key registration failed.', checks: checks);
    }

    // Commit: challenges and code are consumed only now, so a failed
    // upload can be retried with the same keys.
    challenges
      ..markUsed(enrollment.deviceChallengeId)
      ..markUsed(enrollment.approvalChallengeId);
    _otps.remove(enrollment.id);
    _enrollments.remove(enrollment.id);

    final previous = enrollment.previousDeviceId == null
        ? null
        : _devices[enrollment.previousDeviceId];
    if (previous != null && previous.isActive) {
      _retire(previous, DeviceStatus.replaced,
          'replaced by a new enrollment from the same app');
      checks.add(ServerCheck.info('enroll.previous', 'Previous binding retired',
          '${previous.deviceId} and its keys were revoked.'));
    }
    final device = DeviceRecord(
      deviceId: 'dev-${toHex(secureRandomBytes(4))}',
      customerId: DemoCustomer.id,
      platform: enrollment.platform,
      enrolledAt: clock.now(),
      deviceKey: deviceKey,
      approvalKeys: [approvalKey],
    );
    _devices[device.deviceId] = device;
    checks.add(_tierCCheck(device));
    await _saveDevices();
    await audit.record(device.deviceId, 'device.bound',
        detail: '${enrollment.platform.label}; device key '
            '${deviceKey.trustTier.label}, approval key '
            '${approvalKey.trustTier.label} '
            '(${approvalKey.authPolicySummary}).',
        severity: AuditSeverity.success);
    notifyListeners();
    return {
      'ok': true,
      'deviceId': device.deviceId,
      'device': device.toJson(),
      'checks': [for (final c in checks) c.toJson()],
    };
  }

  /// Parses a key registration and verifies its attestation, if any.
  Future<(RegisteredKey?, ServerCheck)> _registerKey({
    required String alias,
    required Object? json,
    required String challengeId,
    required String boundTo,
    required DevicePlatform platform,
  }) async {
    final id = 'enroll.$alias';
    final title = '$alias registered';
    final publicKey = json is Map<String, dynamic> ? json['publicKey'] : null;
    if (json is! Map<String, dynamic> || publicKey is! String) {
      return (null, ServerCheck.fail(id, title, 'No public key sent.'));
    }
    try {
      ParsedPublicKey.parse(publicKey);
    } on FormatException catch (e) {
      return (
        null,
        ServerCheck.fail(id, title, 'Public key does not parse: ${e.message}')
      );
    }
    final chainJson = json['attestationChain'];
    final AttestationReport report;
    if (chainJson is List && chainJson.isNotEmpty) {
      final chain = [for (final c in chainJson) base64.decode(c as String)];
      final challenge = challenges.peek(challengeId,
          purpose: 'attest:$alias', boundTo: boundTo);
      if (challenge is ChallengeOk) {
        report = await _verifyAttestation(
            chain, challenge.challenge.bytes, publicKey);
      } else {
        report = AttestationReport(
          checks: [
            AttestationCheck(
              id: AttestationCheckIds.challenge,
              title: 'Challenge matches',
              status: CheckStatus.fail,
              detail: 'The attestation challenge is unusable: '
                  '${challenge.reason}.',
            ),
          ],
          trustTier: TrustTier.untrusted,
          verifiedAt: clock.now(),
          chain: chain,
        );
      }
    } else {
      report = AttestationReport.notProvided(
        json['attestationNote'] as String? ??
            '${platform.label} sent no key attestation.',
        at: clock.now(),
      );
    }
    final key = RegisteredKey(
      alias: alias,
      publicKey: publicKey,
      registeredAt: clock.now(),
      attestation: report,
      declaredUseDeviceCredentials: json['useDeviceCredentials'] as bool?,
    );
    return (key, _attestationCheck(key));
  }

  Future<AttestationReport> _verifyAttestation(
      List<Uint8List> chain, Uint8List challenge, String publicKey) async {
    if (verifyAttestationInIsolate) {
      return AttestationVerifier.verifyInIsolate(
        chain: chain,
        expectedChallenge: challenge,
        expectedPublicKey: publicKey,
        policy: attestationPolicy,
        trustedRootSpkiSha256: trustedRootSpkiSha256,
        now: clock.now(),
      );
    }
    return AttestationVerifier(
      trustedRootSpkiSha256: trustedRootSpkiSha256,
      now: clock.now,
    ).verify(
      chain: chain,
      expectedChallenge: challenge,
      expectedPublicKey: publicKey,
      policy: attestationPolicy,
    );
  }

  ServerCheck _attestationCheck(RegisteredKey key) {
    final id = 'enroll.${key.alias}';
    final title = '${key.alias} registered';
    final report = key.attestation;
    switch (report.trustTier) {
      case TrustTier.strongBox:
      case TrustTier.tee:
        return ServerCheck.pass(
            id,
            title,
            'Attestation verified: ${report.trustTier.label} key, chain to a '
            'trusted root, challenge and public key match. '
            '${key.authPolicySummary}.');
      case TrustTier.none:
        return ServerCheck.info(
            id,
            title,
            '${report.checks.first.detail} The bank relies on the key alone: '
            '${key.authPolicySummary}.');
      case TrustTier.untrusted:
        final failure = report.failures.isEmpty
            ? 'unknown failure'
            : '${report.failures.first.title}: ${report.failures.first.detail}';
        return ServerCheck.warn(
            id,
            title,
            'Attestation failed ($failure). Registered as untrusted, so it '
            'cannot qualify for tier C.');
    }
  }

  ServerCheck _tierCCheck(DeviceRecord device) {
    final decision = _policy.evaluate(_policy.tierBLimitCents + 1, device);
    return decision.allowed
        ? ServerCheck.pass(
            'policy.tierC', 'Tier C available', '${decision.assurance}.')
        : ServerCheck.warn(
            'policy.tierC', 'Tier C not available', decision.reason!);
  }

  // -------------------------------------------------------------- accounts

  Future<Map<String, dynamic>> _accounts(
          Map<String, dynamic> body, _Ctx ctx) async =>
      {'ok': true, ..._snapshot(ctx.device!)};

  Map<String, dynamic> _snapshot(DeviceRecord device) => {
        'customer': {'id': device.customerId, 'name': DemoCustomer.name},
        'accounts': [
          for (final a in ledger.accountsFor(device.customerId)) a.toJson(),
        ],
        'recent': [
          for (final p in ledger.recentFor(device.customerId)) p.toJson(),
        ],
        'payees': [for (final p in Ledger.payees) p.toJson()],
        'policy': _policy.toJson(),
        'device': device.toJson(),
        'serverTime': clock.now().toIso8601String(),
      };

  // ------------------------------------------------------------- transfers

  Future<Map<String, dynamic>> _prepare(
      Map<String, dynamic> body, _Ctx ctx) async {
    final device = ctx.device!;
    final amount = body['amountCents'];
    final fromId = body['fromAccount'];
    final payeeId = body['payeeId'];
    if (amount is! int || amount <= 0) {
      return _reject('The amount must be a positive number of cents.');
    }
    if ((body['currency'] ?? 'USD') != 'USD') {
      return _reject('Only USD transfers are supported.');
    }
    final account = fromId is String ? ledger.account(fromId) : null;
    if (account == null || account.customerId != device.customerId) {
      return _reject('Unknown account.');
    }
    final payee = payeeId is String ? ledger.payee(payeeId) : null;
    if (payee == null) return _reject('Unknown payee.');
    if (account.balanceCents < amount) {
      return _reject('Insufficient funds: ${account.name} has '
          '${formatCents(account.balanceCents)}.');
    }
    final decision = _policy.evaluate(amount, device);
    if (!decision.allowed) {
      await audit.record(device.deviceId, 'transfer.declined',
          detail: '${formatCents(amount)} to ${payee.name} (tier '
              '${decision.tier.label}): ${decision.reason}',
          severity: AuditSeverity.warning);
      return {
        ..._reject(decision.reason!, code: 'tier'),
        'decision': decision.toJson(),
      };
    }
    final now = clock.now();
    final expires = now.add(Duration(seconds: _policy.approvalTtlSeconds));
    final txnId = 'TX-${toHex(secureRandomBytes(4)).toUpperCase()}';
    // What you see is what you sign: the bank builds the canonical bytes,
    // the app shows exactly these fields and signs exactly these bytes.
    final bytes = canonicalJsonBytes({
      'v': 1,
      'txnId': txnId,
      'amountCents': amount,
      'currency': 'USD',
      'fromAccount': account.id,
      'payee': payee.name,
      'payeeAccount': payee.account,
      'nonce': base64.encode(secureRandomBytes(16)),
      'iat': now.millisecondsSinceEpoch ~/ 1000,
      'exp': expires.millisecondsSinceEpoch ~/ 1000,
      'tier': decision.tier.label,
      'deviceKey': device.deviceKey.fingerprint,
    });
    _pending[txnId] = PendingTransfer._(
      txnId: txnId,
      deviceId: device.deviceId,
      bytes: bytes,
      tier: decision.tier,
      amountCents: amount,
      fromAccount: account.id,
      payee: payee,
      issuedAt: now,
      expiresAt: expires,
    );
    await audit.record(device.deviceId, 'transfer.prepared',
        detail: '$txnId: ${formatCents(amount)} to ${payee.name}, tier '
            '${decision.tier.label}; ${bytes.length} payload bytes issued, '
            'valid ${_policy.approvalTtlSeconds} s.');
    notifyListeners();
    return {
      'ok': true,
      'txnId': txnId,
      'payload': base64.encode(bytes),
      'decision': decision.toJson(),
    };
  }

  Future<Map<String, dynamic>> _confirm(
      Map<String, dynamic> body, _Ctx ctx) async {
    final device = ctx.device!;
    final txnId = body['txnId'];
    final pending = txnId is String ? _pending[txnId] : null;
    final checks = <ServerCheck>[];
    if (pending == null || pending.deviceId != device.deviceId) {
      checks.add(ServerCheck.fail(
          'txn.known',
          'Transaction was issued to this device',
          'No transfer $txnId was prepared for ${device.deviceId} (or it was '
              'purged).'));
      await audit.record(device.deviceId, 'transfer.rejected',
          detail: 'Unknown transaction $txnId.',
          severity: AuditSeverity.danger);
      return _reject(checks.single.detail, code: 'txn', checks: checks);
    }
    final tier = pending.tier;
    checks.add(ServerCheck.pass(
        'txn.known',
        'Transaction was issued to this device',
        '${pending.txnId} was prepared for ${device.deviceId} at '
            '${formatTime(pending.issuedAt)}.'));

    // 1. The nonce is single-use: consumed now, whatever happens next.
    if (pending.used) {
      checks.add(const ServerCheck.fail(
          'txn.nonce',
          'Nonce not used before',
          'This approval was already submitted. Each payload nonce is '
              'accepted once: a replay.'));
    } else {
      pending.used = true;
      checks.add(const ServerCheck.pass('txn.nonce', 'Nonce not used before',
          'Nonce consumed now; submitting it again will be rejected.'));
    }

    // 2. Still within the approval window?
    final now = clock.now();
    final ttl = pending.expiresAt.difference(pending.issuedAt).inSeconds;
    if (now.isBefore(pending.expiresAt)) {
      checks.add(ServerCheck.pass(
          'txn.expiry',
          'Approved within $ttl s',
          'Confirmed ${now.difference(pending.issuedAt).inSeconds} s after '
              'it was issued.'));
    } else {
      checks.add(ServerCheck.fail(
          'txn.expiry',
          'Approved within $ttl s',
          'Issued at ${formatTime(pending.issuedAt)}, expired at '
              '${formatTime(pending.expiresAt)}. Prepare the transfer again.'));
    }

    // 3. Are the signed bytes the bytes the bank issued?
    Uint8List? presented;
    final payloadJson = body['payload'];
    if (payloadJson is String) {
      try {
        presented = base64.decode(payloadJson);
      } on FormatException {
        presented = null;
      }
    }
    if (presented != null && constantTimeEquals(presented, pending.bytes)) {
      checks.add(ServerCheck.pass(
          'payload.issued',
          'Signed bytes are the bytes the bank issued',
          'Byte-identical to the ${pending.bytes.length} bytes issued for '
              '${pending.txnId} (sha256 '
              '${sha256Hex(pending.bytes).substring(0, 12)}…). Amount, payee '
              'and tier come from the bank\'s record, never from a '
              're-serialized client copy.'));
    } else {
      checks.add(ServerCheck.fail(
          'payload.issued',
          'Signed bytes are the bytes the bank issued',
          _describeDifference(presented, pending.bytes)));
    }

    // 4. Signed with the key the tier requires?
    final signer = body['signer'];
    final requiredAlias = tier.requiredAlias;
    if (signer == requiredAlias) {
      checks.add(ServerCheck.pass(
          'tier.signer',
          'Signed with the key tier ${tier.label} requires',
          'Tier ${tier.label} requires $requiredAlias.'));
    } else {
      checks.add(ServerCheck.fail(
          'tier.signer',
          'Signed with the key tier ${tier.label} requires',
          'Tier ${tier.label} requires $requiredAlias, but the app signed '
              'with $signer.'));
    }

    // 5. Does the signature verify with the registered key?
    final key = switch (signer) {
      KeyAliases.deviceBinding => device.deviceKey,
      KeyAliases.approval => device.activeApprovalKey,
      _ => null,
    };
    final signatureJson = body['signature'];
    if (key == null || !key.isActive) {
      checks.add(ServerCheck.fail('signature', 'Approval signature',
          'No active $signer key is registered for ${device.deviceId}.'));
    } else if (presented == null || signatureJson is! String) {
      checks.add(const ServerCheck.fail('signature', 'Approval signature',
          'The payload or the signature is missing.'));
    } else {
      VerifyOutcome outcome;
      try {
        outcome = verifySignature(
            publicKey: key.publicKey,
            message: presented,
            signature: base64.decode(signatureJson));
      } on FormatException {
        outcome = const VerifyOutcome.invalid('signature is not base64');
      }
      final fp = formatFingerprint(key.fingerprint, maxGroups: 4);
      checks.add(outcome.isValid
          ? ServerCheck.pass(
              'signature',
              'Approval signature',
              '${key.description} signature by $signer ($fp) verifies over '
                  'the signed bytes.')
          : ServerCheck.fail(
              'signature',
              'Approval signature',
              'Signature mismatch (${outcome.message}): these bytes are not '
                  'what $signer signed. They were changed after approval.'));
    }

    // 6. Does the tier's policy still hold (keys can be rotated and the
    //    policy edited between prepare and confirm)?
    final decision = _policy.evaluate(pending.amountCents, device);
    if (!decision.allowed) {
      checks.add(ServerCheck.fail(
          'tier.policy', 'Tier ${tier.label} policy', decision.reason!));
    } else if (decision.tier.index > tier.index) {
      checks.add(ServerCheck.fail(
          'tier.policy',
          'Tier ${tier.label} policy',
          'The policy changed after this transfer was prepared: it is now '
              'tier ${decision.tier.label}. Prepare it again.'));
    } else {
      checks.add(ServerCheck.pass(
          'tier.policy', 'Tier ${tier.label} policy', decision.assurance));
    }

    // 7. authenticationType: client-reported and unsigned. Recorded for
    //    audit; contradictions are flagged, never trusted.
    final reported = body['authenticationType'] as String?;
    var anomaly = false;
    final approvalKey = device.activeApprovalKey;
    if (tier == RiskTier.a) {
      checks.add(ServerCheck.info(
          'auth.type',
          'Reported authentication',
          'Silent ${KeyAliases.deviceBinding} key: no user authentication '
              'took place (reported "${reported ?? 'none'}").'));
    } else if (reported == 'credential' &&
        approvalKey != null &&
        approvalKey.expectedBiometricOnly) {
      anomaly = true;
      checks.add(ServerCheck.warn(
          'auth.type',
          'Reported authentication: anomaly',
          approvalKey.attestedUserAuthType == 2
              ? 'The approval key is attested biometric-only (userAuthType 2), '
                  'yet the app reported a device credential. The report is '
                  'unsigned; the hardware enforces the attested policy. '
                  'Flagged for review.'
              : 'The approval key was declared biometric-only, yet the app '
                  'reported a device credential. Flagged for review.'));
    } else {
      checks.add(ServerCheck.info(
          'auth.type',
          'Reported authentication',
          '"${reported ?? 'none'}", as reported by the app. Recorded for '
              'audit only: it is not signed, so trust comes from the key\'s '
              'policy instead.'));
    }

    // 8. Post.
    int? balanceAfter;
    if (checks.any((c) => c.failed)) {
      checks.add(const ServerCheck.info(
          'ledger.post', 'Posted to the ledger', 'Not posted.'));
    } else {
      try {
        final posting = await ledger.debit(
          accountId: pending.fromAccount,
          amountCents: pending.amountCents,
          description: 'Transfer to ${pending.payee.name}',
          txnId: pending.txnId,
          tier: tier,
        );
        balanceAfter = posting.balanceAfterCents;
        checks.add(ServerCheck.pass(
            'ledger.post',
            'Posted to the ledger',
            'Debited ${formatCents(pending.amountCents)} from '
                '${pending.fromAccount}; balance '
                '${formatCents(posting.balanceAfterCents)}.'));
      } on StateError catch (e) {
        checks.add(
            ServerCheck.fail('ledger.post', 'Posted to the ledger', e.message));
      }
    }

    final failure = checks.where((c) => c.failed).firstOrNull;
    final record = TransferRecord(
      txnId: pending.txnId,
      deviceId: device.deviceId,
      amountCents: pending.amountCents,
      currency: 'USD',
      fromAccount: pending.fromAccount,
      payee: pending.payee.name,
      tier: tier,
      status:
          failure == null ? TransferStatus.accepted : TransferStatus.rejected,
      signer: signer as String?,
      authenticationType: reported,
      anomaly: anomaly,
      checks: checks,
      decidedAt: now,
      reason: failure == null ? null : '${failure.title}: ${failure.detail}',
      balanceAfterCents: balanceAfter,
    );
    _transfers.add(record);
    if (_transfers.length > 100) _transfers.removeAt(0);
    await store.write('transfers', [for (final t in _transfers) t.toJson()]);
    final summary = '${pending.txnId}: ${formatCents(pending.amountCents)} to '
        '${pending.payee.name}, tier ${tier.label}, signed by $signer, '
        'reported "${reported ?? 'none'}"';
    if (failure == null) {
      await audit.record(device.deviceId, 'transfer.accepted',
          detail: summary, severity: AuditSeverity.success);
      if (anomaly) {
        await audit.record(device.deviceId, 'transfer.anomaly',
            detail: '${pending.txnId}: reported a device credential for a '
                'biometric-only key.',
            severity: AuditSeverity.warning);
      }
    } else {
      await audit.record(device.deviceId, 'transfer.rejected',
          detail: '$summary — ${record.reason}',
          severity: AuditSeverity.danger);
    }
    notifyListeners();
    return {
      'ok': failure == null,
      'reason': record.reason,
      'transfer': record.toJson(),
      'accounts': _snapshot(device)['accounts'],
      'recent': _snapshot(device)['recent'],
    };
  }

  /// Explains how [presented] differs from [issued], field by field when
  /// both parse as JSON objects.
  static String _describeDifference(Uint8List? presented, Uint8List issued) {
    if (presented == null) return 'No payload was sent back.';
    try {
      final a = jsonDecode(utf8.decode(issued)) as Map<String, dynamic>;
      final b = jsonDecode(utf8.decode(presented));
      if (b is Map<String, dynamic>) {
        final changes = [
          for (final k in {...a.keys, ...b.keys})
            if ('${a[k]}' != '${b[k]}') '$k: ${a[k]} → ${b[k]}',
        ];
        if (changes.isNotEmpty) {
          return 'The payload was modified after the bank issued it '
              '(${changes.join('; ')}). The bank only accepts its own bytes.';
        }
      }
    } on Object {
      // Fall through to the generic message.
    }
    return 'The payload differs from the ${issued.length} bytes the bank '
        'issued. The bank only accepts its own bytes.';
  }

  // -------------------------------------------------------- re-verification

  Future<Map<String, dynamic>> _reverifyBegin(
      Map<String, dynamic> body, _Ctx ctx) async {
    final device = ctx.device!;
    final reason = body['reason'] as String? ?? 'rotation';
    final id = 'rv-${toHex(secureRandomBytes(6))}';
    final challenge = challenges.issue(
        purpose: 'attest:${KeyAliases.approval}',
        boundTo: id,
        ttl: const Duration(minutes: 10));
    _reverifications[id] =
        _PendingReverify(id, device.deviceId, challenge.id, reason);
    _sendOtp(
        id,
        'Step-up Bank: {code} confirms a new approval key on your '
        'device. If this wasn\'t you, call us.');
    await audit.record(device.deviceId, 'approval_key.reverify_begin',
        detail: 'Reason: $reason. Device possession proven by the '
            '${KeyAliases.deviceBinding} request signature; one-time code '
            'sent to ${DemoCustomer.phone}.',
        severity: AuditSeverity.warning);
    return {
      'ok': true,
      'reverifyId': id,
      'otpSentTo': DemoCustomer.phone,
      'attestationChallenge': challenge.base64Value,
      'checks': [
        ServerCheck.pass(
                'reverify.device',
                'Same device',
                'This request was signed by the silent '
                    '${KeyAliases.deviceBinding} key of ${device.deviceId}. '
                    'It proves the device, not the person: the one-time code '
                    'is the second factor.')
            .toJson(),
      ],
    };
  }

  Future<Map<String, dynamic>> _reverifyFinish(
      Map<String, dynamic> body, _Ctx ctx) async {
    final device = ctx.device!;
    final id = body['reverifyId'];
    final pending = id is String ? _reverifications[id] : null;
    if (pending == null || pending.deviceId != device.deviceId) {
      return _reject('Unknown or expired re-verification: start again.');
    }
    final checks = <ServerCheck>[_checkOtp(pending.id, body['otp'])];
    if (checks.last.failed) {
      await audit.record(device.deviceId, 'approval_key.otp_failed',
          detail: checks.last.detail, severity: AuditSeverity.warning);
      return _reject(checks.last.detail, code: 'otp', checks: checks);
    }
    final (key, keyCheck) = await _registerKey(
      alias: KeyAliases.approval,
      json: body['approvalKey'],
      challengeId: pending.challengeId,
      boundTo: pending.id,
      platform: device.platform,
    );
    checks.add(keyCheck);
    if (key == null) return _reject('Key registration failed.', checks: checks);
    challenges.markUsed(pending.challengeId);
    _otps.remove(pending.id);
    _reverifications.remove(pending.id);
    final now = clock.now();
    for (final old in device.approvalKeys) {
      if (!old.isActive) continue;
      old
        ..status = KeyStatus.revoked
        ..revokedAt = now
        ..revokeReason = 'rotated (${pending.reason})';
      checks.add(ServerCheck.info(
          'reverify.revoked',
          'Old approval key revoked',
          '${formatFingerprint(old.fingerprint, maxGroups: 4)} no longer '
              'accepted.'));
    }
    device.approvalKeys.add(key);
    checks.add(_tierCCheck(device));
    await _saveDevices();
    await audit.record(device.deviceId, 'approval_key.rotated',
        detail: 'Reason: ${pending.reason}. New key '
            '${formatFingerprint(key.fingerprint, maxGroups: 4)} '
            '(${key.trustTier.label}, ${key.authPolicySummary}).',
        severity: AuditSeverity.success);
    notifyListeners();
    return {
      'ok': true,
      'device': device.toJson(),
      'checks': [for (final c in checks) c.toJson()],
    };
  }

  Future<Map<String, dynamic>> _unbind(
      Map<String, dynamic> body, _Ctx ctx) async {
    final device = ctx.device!;
    _retire(device, DeviceStatus.unbound, 'unbound by the user');
    await _saveDevices();
    await audit.record(device.deviceId, 'device.unbound',
        detail: 'Device and keys revoked at the user\'s request.',
        severity: AuditSeverity.warning);
    notifyListeners();
    return {'ok': true};
  }

  // --------------------------------------------------------------- helpers

  void _retire(DeviceRecord device, DeviceStatus status, String reason) {
    final now = clock.now();
    device.status = status;
    for (final k in [device.deviceKey, ...device.approvalKeys]) {
      if (!k.isActive) continue;
      k
        ..status = KeyStatus.revoked
        ..revokedAt = now
        ..revokeReason = reason;
    }
    _pending.removeWhere((_, p) => p.deviceId == device.deviceId);
  }

  void _sendOtp(String subject, String template) {
    final code = (100000 + _random.nextInt(900000)).toString();
    final now = clock.now();
    _otps[subject] = _Otp(code, now.add(const Duration(minutes: 5)));
    outbox.add(SimulatedSms(
      to: DemoCustomer.phone,
      text: template.replaceAll('{code}', code),
      code: code,
      subject: subject,
      sentAt: now,
    ));
  }

  ServerCheck _checkOtp(String subject, Object? presented) {
    const id = 'otp';
    const title = 'One-time code';
    final otp = _otps[subject];
    if (otp == null) {
      return const ServerCheck.fail(
          id, title, 'No active code: request a new one.');
    }
    if (!clock.now().isBefore(otp.expiresAt)) {
      _otps.remove(subject);
      return const ServerCheck.fail(
          id, title, 'The code expired: request a new one.');
    }
    final ok = presented is String &&
        constantTimeEquals(
            utf8.encode(presented.trim()), utf8.encode(otp.code));
    if (!ok) {
      otp.attemptsLeft--;
      if (otp.attemptsLeft <= 0) _otps.remove(subject);
      return ServerCheck.fail(
          id,
          title,
          otp.attemptsLeft <= 0
              ? 'Wrong code; no attempts left: request a new one.'
              : 'Wrong code (${otp.attemptsLeft} attempts left).');
    }
    return const ServerCheck.pass(id, title,
        'Matched the code sent to ${DemoCustomer.phone} (simulated SMS).');
  }

  Map<String, dynamic> _reject(String reason,
          {String code = 'rejected', List<ServerCheck> checks = const []}) =>
      {
        'ok': false,
        'reason': reason,
        'reasonCode': code,
        'checks': [for (final c in checks) c.toJson()],
      };

  Future<void> _saveDevices() => store.write('devices', {
        for (final d in _devices.values) d.deviceId: d.toJson(),
      });
}
