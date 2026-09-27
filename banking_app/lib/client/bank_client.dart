/// The app's side of the bank API: every call is signed silently with the
/// `device_binding` key, and every signed request is logged with the
/// server's verdict.
library;

import 'dart:convert';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';

import '../server/models.dart';
import '../server/request_signing.dart';
import '../server/risk_policy.dart';
import 'transaction_payload.dart';

/// The customer id the (simulated) login screen established.
const String demoCustomerId = 'cust-alex';

/// What went wrong with a bank call.
enum BankErrorKind {
  /// The plugin could not sign (see [BankError.code]).
  signing,

  /// The call never reached the bank.
  network,

  /// The bank rejected the request.
  rejected,
}

/// A failed bank call.
class BankError implements Exception {
  /// Creates an error.
  const BankError(
    this.kind,
    this.message, {
    this.code,
    this.reasonCode,
    this.requestChecks = const [],
    this.checks = const [],
    this.decision,
  });

  /// Category.
  final BankErrorKind kind;

  /// Human-readable message.
  final String message;

  /// Plugin error code for [BankErrorKind.signing].
  final BiometricError? code;

  /// Server reason (`device`, `timestamp`, `signature`, `replay`, `otp`,
  /// `tier` …).
  final String? reasonCode;

  /// Request-signature checks from the server.
  final List<ServerCheck> requestChecks;

  /// Business checks from the server.
  final List<ServerCheck> checks;

  /// Tier decision, for declined transfers.
  final TierDecision? decision;

  /// The server no longer knows this device (or it was unbound).
  bool get deviceNotRecognised =>
      kind == BankErrorKind.rejected && reasonCode == 'device';

  @override
  String toString() => 'BankError(${kind.name}): $message';
}

/// State of a logged request.
enum RequestStatus {
  /// Waiting for the plugin.
  signing,

  /// Signed; waiting for the bank.
  sent,

  /// The bank verified the request signature.
  verified,

  /// The bank rejected the request signature, timestamp or id.
  rejected,

  /// The call failed in transit.
  networkError,

  /// The plugin could not sign.
  signingFailed,
}

/// One signed request, as the app built it and the bank judged it.
class RequestLogEntry {
  RequestLogEntry._({
    required this.id,
    required this.time,
    required this.route,
    required this.timestampMs,
    required this.requestId,
    required this.bodySha256,
    required this.canonical,
  });

  /// Sequence number.
  final int id;

  /// When it was created (client clock).
  final DateTime time;

  /// Route.
  final BankRoute route;

  /// Signed timestamp.
  final int timestampMs;

  /// Signed request id.
  final String requestId;

  /// Signed body hash.
  final String bodySha256;

  /// The exact string signed.
  final String canonical;

  /// Status.
  RequestStatus status = RequestStatus.signing;

  /// Signature (base64).
  String? signature;

  /// `authenticationType` of the signing operation.
  AuthenticationType? authenticationType;

  /// Time the plugin took to sign.
  Duration? signingTime;

  /// The bank's request checks.
  List<ServerCheck> serverChecks = const [];

  /// Extra detail (errors, business outcome).
  String? detail;
}

/// Signed requests, newest last.
class RequestLog with Observable {
  final List<RequestLogEntry> _entries = [];
  int _next = 1;

  /// Entries, oldest first.
  List<RequestLogEntry> get entries => List.unmodifiable(_entries);

  RequestLogEntry _add(RequestLogEntry Function(int id) create) {
    final entry = create(_next++);
    _entries.add(entry);
    if (_entries.length > 100) _entries.removeAt(0);
    notifyListeners();
    return entry;
  }

  /// Signals that an entry changed.
  void updated() => notifyListeners();

  /// Removes every entry.
  void clear() {
    _entries.clear();
    notifyListeners();
  }
}

/// Faults that model a compromised app: code running inside the app can use
/// the silent `device_binding` key, but not the biometric approval key.
class ClientFaults with Observable {
  bool _alterAmountAfterApproval = false;

  /// Change the amount of the next approved payload before sending it.
  bool get alterAmountAfterApproval => _alterAmountAfterApproval;

  set alterAmountAfterApproval(bool value) {
    _alterAmountAfterApproval = value;
    notifyListeners();
  }

  /// Returns and clears [alterAmountAfterApproval].
  bool takeAlterAmount() {
    final value = _alterAmountAfterApproval;
    if (value) alterAmountAfterApproval = false;
    return value;
  }

  /// Clears every fault.
  void clear() => alterAmountAfterApproval = false;
}

/// A request envelope signed with `device_binding`.
class SignedEnvelope {
  const SignedEnvelope._({
    required this.envelope,
    required this.canonical,
    required this.result,
    required this.timestampMs,
    required this.requestId,
    required this.bodySha256,
    required this.elapsed,
  });

  /// `{auth, body}`, ready to send (only meaningful when signing succeeded).
  final Map<String, dynamic> envelope;

  /// The string that was signed.
  final String canonical;

  /// The plugin result.
  final SignatureResult result;

  /// Signed timestamp.
  final int timestampMs;

  /// Signed request id.
  final String requestId;

  /// Signed body hash.
  final String bodySha256;

  /// How long signing took.
  final Duration elapsed;

  /// Whether the plugin produced a signature.
  bool get ok =>
      result.code == BiometricError.success && result.signature != null;
}

/// Signs [body] for [route] with the silent `device_binding` key using
/// `createSignature` (text payload).
///
/// On Android, iOS and macOS the key was created with
/// `requireAuthentication: false`, so this never prompts. Windows Hello
/// prompts anyway and shows [promptMessage].
Future<SignedEnvelope> signRequest({
  required BiometricSignature api,
  required Clock clock,
  required BankRoute route,
  required Map<String, dynamic> body,
  String? deviceId,
  String promptMessage = 'Confirm it\'s you to contact Step-up Bank',
}) async {
  final timestampMs = clock.now().millisecondsSinceEpoch;
  final requestId = toHex(secureRandomBytes(12));
  final digest = bodyDigest(body);
  final canonical = canonicalRequest(
    method: route.method,
    path: route.path,
    timestampMs: timestampMs,
    bodySha256: digest,
    requestId: requestId,
  );
  final stopwatch = Stopwatch()..start();
  final result = await api.createSignature(
    payload: canonical,
    keyAlias: KeyAliases.deviceBinding,
    promptMessage: promptMessage,
  );
  stopwatch.stop();
  return SignedEnvelope._(
    envelope: {
      'auth': RequestAuth(
        deviceId: deviceId,
        keyAlias: KeyAliases.deviceBinding,
        timestampMs: timestampMs,
        requestId: requestId,
        signature: result.signature ?? '',
      ).toJson(),
      'body': body,
    },
    canonical: canonical,
    result: result,
    timestampMs: timestampMs,
    requestId: requestId,
    bodySha256: digest,
    elapsed: stopwatch.elapsed,
  );
}

/// `/enroll/begin` response.
class EnrollmentStart {
  EnrollmentStart._(
      this.enrollmentId, this.customerName, this.otpSentTo, this._challenges);

  factory EnrollmentStart._fromJson(Map<String, dynamic> json) =>
      EnrollmentStart._(
        json['enrollmentId'] as String,
        json['customerName'] as String,
        json['otpSentTo'] as String,
        {
          for (final e
              in (json['attestationChallenges'] as Map<String, dynamic>)
                  .entries)
            e.key: base64.decode(e.value as String),
        },
      );

  /// Enrollment id (also the subject of the simulated SMS).
  final String enrollmentId;

  /// Customer name.
  final String customerName;

  /// Where the one-time code was sent.
  final String otpSentTo;

  final Map<String, List<int>> _challenges;

  /// The attestation challenge for [alias].
  List<int>? challengeFor(String alias) => _challenges[alias];
}

/// `/enroll/finish` or `/approval-key/reverify/finish` response.
class KeyRegistrationResult {
  const KeyRegistrationResult._(this.device, this.checks, this.requestChecks);

  /// The device record the bank now holds.
  final DeviceRecord device;

  /// The bank's checks (one-time code, attestation, tier C eligibility).
  final List<ServerCheck> checks;

  /// Request-signature checks.
  final List<ServerCheck> requestChecks;
}

/// `/approval-key/reverify/begin` response.
class ReverifyStart {
  const ReverifyStart._(
      this.reverifyId, this.otpSentTo, this.challenge, this.checks);

  /// Re-verification id (also the subject of the simulated SMS).
  final String reverifyId;

  /// Where the one-time code was sent.
  final String otpSentTo;

  /// Attestation challenge for the new approval key.
  final List<int> challenge;

  /// The bank's checks.
  final List<ServerCheck> checks;
}

/// `/accounts` response.
class AccountsSnapshot {
  AccountsSnapshot._({
    required this.customerName,
    required this.accounts,
    required this.recent,
    required this.payees,
    required this.policy,
    required this.device,
    required this.fetchedAt,
  });

  factory AccountsSnapshot._fromJson(
          Map<String, dynamic> json, DateTime fetchedAt) =>
      AccountsSnapshot._(
        customerName:
            (json['customer'] as Map<String, dynamic>)['name'] as String,
        accounts: _accounts(json['accounts']),
        recent: _postings(json['recent']),
        payees: [
          for (final p in json['payees'] as List<dynamic>)
            Payee.fromJson(p as Map<String, dynamic>),
        ],
        policy: RiskPolicy.fromJson(json['policy'] as Map<String, dynamic>),
        device: DeviceRecord.fromJson(json['device'] as Map<String, dynamic>),
        fetchedAt: fetchedAt,
      );

  /// Customer name.
  final String customerName;

  /// Accounts.
  final List<Account> accounts;

  /// Recent postings, newest first.
  final List<Posting> recent;

  /// Saved payees.
  final List<Payee> payees;

  /// The bank's policy (for the tier preview).
  final RiskPolicy policy;

  /// What the bank knows about this device.
  final DeviceRecord device;

  /// When it was fetched.
  final DateTime fetchedAt;

  /// Copy with new balances and postings (after a transfer).
  AccountsSnapshot withActivity(List<Account> accounts, List<Posting> recent) =>
      AccountsSnapshot._(
        customerName: customerName,
        accounts: accounts,
        recent: recent,
        payees: payees,
        policy: policy,
        device: device,
        fetchedAt: fetchedAt,
      );

  /// Copy with a new device record (after a key rotation).
  AccountsSnapshot withDevice(DeviceRecord device) => AccountsSnapshot._(
        customerName: customerName,
        accounts: accounts,
        recent: recent,
        payees: payees,
        policy: policy,
        device: device,
        fetchedAt: fetchedAt,
      );
}

List<Account> _accounts(Object? json) => [
      for (final a in json as List<dynamic>)
        Account.fromJson(a as Map<String, dynamic>),
    ];

List<Posting> _postings(Object? json) => [
      for (final p in json as List<dynamic>)
        Posting.fromJson(p as Map<String, dynamic>),
    ];

/// `/transfers/prepare` response.
class PreparedTransfer {
  const PreparedTransfer._(this.payload, this.decision);

  /// The issued payload, decoded and validated.
  final TransactionPayload payload;

  /// The bank's tier decision.
  final TierDecision decision;
}

/// `/transfers/confirm` response.
class ConfirmResult {
  const ConfirmResult._({
    required this.requestOk,
    required this.requestChecks,
    required this.checks,
    required this.reason,
    this.transfer,
    this.accounts,
    this.recent,
  });

  /// Whether the request signature layer accepted the call.
  final bool requestOk;

  /// Request-signature checks.
  final List<ServerCheck> requestChecks;

  /// Transfer checks (empty when the request layer rejected the call).
  final List<ServerCheck> checks;

  /// Rejection reason.
  final String? reason;

  /// The bank's decision record.
  final TransferRecord? transfer;

  /// Balances after the decision.
  final List<Account>? accounts;

  /// Postings after the decision.
  final List<Posting>? recent;

  /// Whether the transfer was posted.
  bool get accepted => transfer?.accepted ?? false;
}

/// The bank API as the app uses it.
class BankClient {
  /// Creates a client.
  BankClient({required this.api, required this.transport, required this.clock});

  /// The plugin.
  final BiometricSignature api;

  /// The (mock) network.
  final MockTransport transport;

  /// The device clock (skewable in the console).
  final Clock clock;

  /// The bound device id, once enrolled.
  String? deviceId;

  /// Signed requests.
  final RequestLog requestLog = RequestLog();

  /// Compromised-app faults.
  final ClientFaults faults = ClientFaults();

  Map<String, dynamic>? _lastConfirmBody;

  /// Whether [resubmitLastConfirm] has something to resend.
  bool get canResubmitLastConfirm => _lastConfirmBody != null;

  /// Forgets per-device state (reset, unbind).
  void reset() {
    deviceId = null;
    _lastConfirmBody = null;
    faults.clear();
    requestLog.clear();
  }

  Future<Map<String, dynamic>> _unsigned(
      BankRoute route, Map<String, dynamic> body) async {
    try {
      return await transport.call(route.path, body);
    } on TransportException catch (e) {
      throw BankError(BankErrorKind.network, e.message);
    }
  }

  Future<Map<String, dynamic>> _signed(
      BankRoute route, Map<String, dynamic> body) async {
    if (route.auth == RouteAuth.deviceKey && deviceId == null) {
      throw const BankError(
          BankErrorKind.rejected, 'This device is not bound to the bank yet.',
          reasonCode: 'device');
    }
    final signed = await signRequest(
      api: api,
      clock: clock,
      route: route,
      body: body,
      deviceId: route.auth == RouteAuth.deviceKey ? deviceId : null,
    );
    final entry = requestLog._add((id) => RequestLogEntry._(
          id: id,
          time: clock.now(),
          route: route,
          timestampMs: signed.timestampMs,
          requestId: signed.requestId,
          bodySha256: signed.bodySha256,
          canonical: signed.canonical,
        ))
      ..signingTime = signed.elapsed
      ..authenticationType = signed.result.authenticationType;
    if (!signed.ok) {
      final code = signed.result.code ?? BiometricError.unknown;
      entry
        ..status = RequestStatus.signingFailed
        ..detail = '${code.name}: ${signed.result.error ?? ''}';
      requestLog.updated();
      throw BankError(BankErrorKind.signing,
          signed.result.error ?? 'Could not sign the request (${code.name})',
          code: code);
    }
    entry
      ..signature = signed.result.signature
      ..status = RequestStatus.sent;
    requestLog.updated();
    final Map<String, dynamic> response;
    try {
      response = await transport.call(route.path, signed.envelope);
    } on TransportException catch (e) {
      entry
        ..status = RequestStatus.networkError
        ..detail = e.message;
      requestLog.updated();
      throw BankError(BankErrorKind.network, e.message);
    }
    final requestOk = response['requestOk'] == true;
    entry
      ..serverChecks = ServerCheck.listFromJson(response['requestChecks'])
      ..status = requestOk ? RequestStatus.verified : RequestStatus.rejected
      ..detail = requestOk
          ? (response['ok'] == false
              ? 'Authenticated, but declined: ${response['reason']}'
              : null)
          : response['reason'] as String?;
    requestLog.updated();
    return response;
  }

  static Never _throwRejected(Map<String, dynamic> response) {
    final decision = response['decision'];
    throw BankError(
      BankErrorKind.rejected,
      response['reason'] as String? ?? 'Rejected by the bank',
      reasonCode: (response['rejection'] ?? response['reasonCode']) as String?,
      requestChecks: ServerCheck.listFromJson(response['requestChecks']),
      checks: ServerCheck.listFromJson(response['checks']),
      decision: decision is Map<String, dynamic>
          ? TierDecision.fromJson(decision)
          : null,
    );
  }

  /// Starts binding this device: the bank sends a one-time code and issues
  /// attestation challenges.
  Future<EnrollmentStart> enrollBegin(
      {required DevicePlatform platform, String? previousDeviceId}) async {
    final response = await _unsigned(BankRoutes.enrollBegin, {
      'customerId': demoCustomerId,
      'platform': platform.name,
      'previousDeviceId': previousDeviceId,
    });
    if (response['ok'] != true) _throwRejected(response);
    return EnrollmentStart._fromJson(response);
  }

  /// Registers both keys. The request is signed by the `device_binding` key
  /// whose public key is in [body] (proof of possession).
  Future<KeyRegistrationResult> enrollFinish(Map<String, dynamic> body) async {
    final response = await _signed(BankRoutes.enrollFinish, body);
    if (response['ok'] != true) _throwRejected(response);
    deviceId = response['deviceId'] as String;
    return _registration(response);
  }

  static KeyRegistrationResult _registration(Map<String, dynamic> response) =>
      KeyRegistrationResult._(
        DeviceRecord.fromJson(response['device'] as Map<String, dynamic>),
        ServerCheck.listFromJson(response['checks']),
        ServerCheck.listFromJson(response['requestChecks']),
      );

  /// Accounts, activity, payees, policy and the device record.
  Future<AccountsSnapshot> fetchAccounts() async {
    final response = await _signed(BankRoutes.accounts, const {});
    if (response['ok'] != true) _throwRejected(response);
    return AccountsSnapshot._fromJson(response, clock.now());
  }

  /// Asks the bank to prepare a transfer. Returns the payload to approve;
  /// throws [BankError] when the bank declines (e.g. tier not allowed).
  Future<PreparedTransfer> prepareTransfer({
    required String fromAccount,
    required String payeeId,
    required int amountCents,
  }) async {
    final response = await _signed(BankRoutes.prepare, {
      'fromAccount': fromAccount,
      'payeeId': payeeId,
      'amountCents': amountCents,
      'currency': 'USD',
    });
    if (response['ok'] != true) _throwRejected(response);
    final TransactionPayload payload;
    try {
      payload = TransactionPayload.decodeBase64(response['payload'] as String);
    } on FormatException catch (e) {
      throw BankError(BankErrorKind.rejected,
          'The app refused the bank\'s payload: ${e.message}');
    }
    return PreparedTransfer._(payload,
        TierDecision.fromJson(response['decision'] as Map<String, dynamic>));
  }

  /// Sends an approval signature. A rejection is returned (not thrown) so
  /// the receipt can show the verification trace.
  Future<ConfirmResult> confirmTransfer({
    required String txnId,
    required List<int> payload,
    required String signature,
    required String signer,
    required AuthenticationType? authenticationType,
  }) {
    final body = {
      'txnId': txnId,
      'payload': base64.encode(payload),
      'signature': signature,
      'signer': signer,
      'authenticationType': authenticationType?.name,
    };
    _lastConfirmBody = body;
    return _confirm(body);
  }

  /// Sends the last confirmation again in a *fresh* signed request (new
  /// timestamp and request id), as code inside a compromised app could.
  /// The bank rejects it because the payload nonce is single-use.
  Future<ConfirmResult> resubmitLastConfirm() {
    final body = _lastConfirmBody;
    if (body == null) throw StateError('Nothing to resubmit');
    return _confirm(body);
  }

  Future<ConfirmResult> _confirm(Map<String, dynamic> body) async {
    final response = await _signed(BankRoutes.confirm, body);
    return parseConfirmResponse(response);
  }

  /// Parses a `/transfers/confirm` response (also used for the console's
  /// raw replay).
  static ConfirmResult parseConfirmResponse(Map<String, dynamic> response) {
    final transfer = response['transfer'];
    final record = transfer is Map<String, dynamic>
        ? TransferRecord.fromJson(transfer)
        : null;
    return ConfirmResult._(
      requestOk: response['requestOk'] == true,
      requestChecks: ServerCheck.listFromJson(response['requestChecks']),
      checks: record?.checks ?? ServerCheck.listFromJson(response['checks']),
      reason: response['reason'] as String?,
      transfer: record,
      accounts:
          response['accounts'] == null ? null : _accounts(response['accounts']),
      recent: response['recent'] == null ? null : _postings(response['recent']),
    );
  }

  /// Starts re-verification for a new approval key. Signed silently by
  /// `device_binding`, which still works after an enrollment change.
  Future<ReverifyStart> reverifyBegin(String reason) async {
    final response =
        await _signed(BankRoutes.reverifyBegin, {'reason': reason});
    if (response['ok'] != true) _throwRejected(response);
    return ReverifyStart._(
      response['reverifyId'] as String,
      response['otpSentTo'] as String,
      base64.decode(response['attestationChallenge'] as String),
      ServerCheck.listFromJson(response['checks']),
    );
  }

  /// Registers the new approval key; the bank revokes the old one.
  Future<KeyRegistrationResult> reverifyFinish(
      Map<String, dynamic> body) async {
    final response = await _signed(BankRoutes.reverifyFinish, body);
    if (response['ok'] != true) _throwRejected(response);
    return _registration(response);
  }

  /// Asks the bank to revoke this device and its keys.
  Future<void> unbind() async {
    final response = await _signed(BankRoutes.unbind, const {});
    if (response['ok'] != true) _throwRejected(response);
  }
}
