/// Request signing with the silent `device_binding` key.
///
/// Every API call carries a signature over
/// `METHOD\nPATH\nTIMESTAMP\nsha256(body)\nrequestId`. The server checks the
/// timestamp against its clock (±60 s by default), remembers request ids
/// (replay cache) and verifies the signature with the registered key.
///
/// The client and the server both use [canonicalRequest] and [bodyDigest]:
/// the two sides must build byte-identical strings.
library;

import 'dart:convert';

import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';

import '../money.dart';
import 'models.dart';

/// How a route authenticates the caller.
enum RouteAuth {
  /// Not signed (starting an enrollment).
  none,

  /// Signed with the device's registered `device_binding` key.
  deviceKey,

  /// Signed with the `device_binding` key carried in the body (enrollment:
  /// proof of possession of the key being registered).
  selfSigned,
}

/// A mock-server endpoint.
class BankRoute {
  /// Creates a route.
  const BankRoute(this.method, this.path, this.auth);

  /// HTTP-style method, part of the signed string.
  final String method;

  /// Path, part of the signed string (and the [MockTransport] route).
  final String path;

  /// Authentication.
  final RouteAuth auth;

  @override
  String toString() => '$method $path';
}

/// The bank's API.
abstract final class BankRoutes {
  /// Starts an enrollment: OTP + attestation challenges.
  static const enrollBegin = BankRoute('POST', '/enroll/begin', RouteAuth.none);

  /// Registers both keys (signed by the new device_binding key).
  static const enrollFinish =
      BankRoute('POST', '/enroll/finish', RouteAuth.selfSigned);

  /// Accounts, recent activity, payees, policy and the device record.
  static const accounts = BankRoute('GET', '/accounts', RouteAuth.deviceKey);

  /// Validates a transfer and issues the payload bytes to approve.
  static const prepare =
      BankRoute('POST', '/transfers/prepare', RouteAuth.deviceKey);

  /// Verifies the approval signature and posts the transfer.
  static const confirm =
      BankRoute('POST', '/transfers/confirm', RouteAuth.deviceKey);

  /// Starts re-verification: OTP + attestation challenge for a new
  /// approval key.
  static const reverifyBegin =
      BankRoute('POST', '/approval-key/reverify/begin', RouteAuth.deviceKey);

  /// Rotates the approval key.
  static const reverifyFinish =
      BankRoute('POST', '/approval-key/reverify/finish', RouteAuth.deviceKey);

  /// Unbinds the device.
  static const unbind =
      BankRoute('POST', '/device/unbind', RouteAuth.deviceKey);

  /// Every route.
  static const List<BankRoute> all = [
    enrollBegin,
    enrollFinish,
    accounts,
    prepare,
    confirm,
    reverifyBegin,
    reverifyFinish,
    unbind,
  ];
}

/// The string the `device_binding` key signs for a request.
String canonicalRequest({
  required String method,
  required String path,
  required int timestampMs,
  required String bodySha256,
  required String requestId,
}) =>
    '$method\n$path\n$timestampMs\n$bodySha256\n$requestId';

/// SHA-256 (hex) of the canonical JSON of [body]. Throws [ArgumentError]
/// for values canonical JSON does not allow (e.g. decimals).
String bodyDigest(Map<String, dynamic> body) =>
    sha256Hex(canonicalJsonBytes(body));

/// The `auth` block of a signed request envelope.
class RequestAuth {
  /// Creates the block.
  const RequestAuth({
    required this.keyAlias,
    required this.timestampMs,
    required this.requestId,
    required this.signature,
    this.deviceId,
  });

  /// Parses [json], or returns `null` if it is malformed.
  static RequestAuth? tryParse(Object? json) {
    if (json is! Map<String, dynamic>) return null;
    final ts = json['timestamp'];
    final id = json['requestId'];
    final sig = json['signature'];
    final alias = json['keyAlias'];
    final device = json['deviceId'];
    if (ts is! int || id is! String || sig is! String || alias is! String) {
      return null;
    }
    if (device != null && device is! String) return null;
    return RequestAuth(
      keyAlias: alias,
      timestampMs: ts,
      requestId: id,
      signature: sig,
      deviceId: device as String?,
    );
  }

  /// Registered device id (absent while enrolling).
  final String? deviceId;

  /// Always `device_binding`.
  final String keyAlias;

  /// Client clock, milliseconds since the epoch (UTC).
  final int timestampMs;

  /// Random, single-use request id.
  final String requestId;

  /// Signature (base64) over [canonicalRequest].
  final String signature;

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'deviceId': deviceId,
        'keyAlias': keyAlias,
        'timestamp': timestampMs,
        'requestId': requestId,
        'signature': signature,
      };
}

/// Why a request was rejected.
enum RequestRejection {
  /// Missing or malformed `auth` / `body`.
  malformed,

  /// Unknown, unbound or revoked device.
  device,

  /// Timestamp outside the allowed window.
  timestamp,

  /// Signature does not verify.
  signature,

  /// Request id seen before.
  replay,
}

/// The outcome of [RequestVerifier.verify].
class RequestVerification {
  /// Creates a result.
  const RequestVerification(this.checks, this.rejection);

  /// Every check, in order.
  final List<ServerCheck> checks;

  /// The first failure, or `null` when accepted.
  final RequestRejection? rejection;

  /// Whether the request is authentic and fresh.
  bool get ok => rejection == null;

  /// The first failing check's detail.
  String? get reason {
    for (final c in checks) {
      if (c.failed) return '${c.title}: ${c.detail}';
    }
    return null;
  }
}

/// Server side of request signing.
class RequestVerifier {
  /// Creates a verifier using [clock]. The replay window must be longer than
  /// twice [maxSkew] so every replay within the timestamp window is caught.
  RequestVerifier({
    required this.clock,
    this.maxSkew = const Duration(seconds: 60),
    ReplayCache? replayCache,
  }) : replayCache = replayCache ??
            ReplayCache(window: const Duration(minutes: 10), clock: clock);

  /// The bank's clock.
  final Clock clock;

  /// Allowed clock difference.
  Duration maxSkew;

  /// Request ids already seen.
  final ReplayCache replayCache;

  /// Verifies [envelope] (`{auth, body}`) for [route] against [publicKey],
  /// the key the server holds for the device (or, for
  /// [RouteAuth.selfSigned], the key in the body). When [publicKey] is
  /// `null`, [keyProblem] explains why.
  RequestVerification verify({
    required BankRoute route,
    required Map<String, dynamic> envelope,
    required String? publicKey,
    String? keyProblem,
  }) {
    final auth = RequestAuth.tryParse(envelope['auth']);
    final body = envelope['body'];
    if (auth == null || body is! Map<String, dynamic>) {
      return const RequestVerification([
        ServerCheck.fail('request.envelope', 'Request is well-formed',
            'The auth block or the body is missing or malformed.'),
      ], RequestRejection.malformed);
    }

    final checks = <ServerCheck>[];
    RequestRejection? rejection;
    void fail(ServerCheck check, RequestRejection why) {
      checks.add(check);
      rejection ??= why;
    }

    // 1. Whose key?
    ParsedPublicKey? key;
    if (publicKey != null) {
      try {
        key = ParsedPublicKey.parse(publicKey);
      } on FormatException catch (e) {
        keyProblem = 'Registered key does not parse: ${e.message}';
      }
    }
    if (key == null) {
      fail(
          ServerCheck.fail('request.device', 'Device key is registered',
              keyProblem ?? 'No key for this device.'),
          RequestRejection.device);
    } else {
      checks.add(ServerCheck.pass(
        'request.device',
        'Device key is registered',
        route.auth == RouteAuth.selfSigned
            ? 'Enrollment: signed by the device_binding key being registered '
                '(${key.description}, ${formatFingerprint(key.fingerprint, maxGroups: 4)}) '
                '— proof of possession.'
            : '${auth.keyAlias} of ${auth.deviceId} '
                '(${key.description}, ${formatFingerprint(key.fingerprint, maxGroups: 4)}).',
      ));
    }

    // 2. Fresh?
    final now = clock.now();
    final signedAt =
        DateTime.fromMillisecondsSinceEpoch(auth.timestampMs, isUtc: true);
    final skew = signedAt.difference(now);
    final skewText = '${skew.isNegative ? '-' : '+'}'
        '${(skew.inMilliseconds.abs() / 1000).toStringAsFixed(1)} s';
    if (skew.abs() <= maxSkew) {
      checks.add(ServerCheck.pass(
        'request.timestamp',
        'Timestamp within ±${maxSkew.inSeconds} s',
        'Signed at ${formatTime(signedAt)}; device clock is $skewText off '
            'the bank\'s clock.',
      ));
    } else {
      fail(
          ServerCheck.fail(
            'request.timestamp',
            'Timestamp within ±${maxSkew.inSeconds} s',
            'Signed at ${formatTime(signedAt)}, $skewText off the bank\'s '
                'clock (${formatTime(now)}). A stale or future request is '
                'rejected even when its signature is valid.',
          ),
          RequestRejection.timestamp);
    }

    // 3. Authentic?
    var signatureOk = false;
    if (key == null) {
      checks.add(const ServerCheck.info('request.signature',
          'Request signature', 'Not checked: no registered key.'));
    } else {
      String? digest;
      try {
        digest = bodyDigest(body);
      } on ArgumentError catch (e) {
        fail(
            ServerCheck.fail('request.signature', 'Request signature',
                'The body is not canonical JSON: ${e.message}'),
            RequestRejection.signature);
      }
      if (digest != null) {
        final message = canonicalRequest(
          method: route.method,
          path: route.path,
          timestampMs: auth.timestampMs,
          bodySha256: digest,
          requestId: auth.requestId,
        );
        VerifyOutcome outcome;
        try {
          outcome = verifySignatureWithKey(key,
              message: utf8.encode(message),
              signature: base64.decode(auth.signature));
        } on FormatException {
          outcome = const VerifyOutcome.invalid('Signature is not base64');
        }
        signatureOk = outcome.isValid;
        if (signatureOk) {
          checks.add(ServerCheck.pass(
            'request.signature',
            'Request signature',
            '${SignatureAlgorithm.defaultFor(key)?.label ?? key.description} '
                'signature verifies over "${route.method} ${route.path}", '
                'the timestamp, sha256(body) = ${digest.substring(0, 12)}… '
                'and the request id.',
          ));
        } else {
          fail(
              ServerCheck.fail(
                'request.signature',
                'Request signature',
                'Signature mismatch (${outcome.message}): the method, path, '
                    'timestamp, body or request id changed after the device '
                    'signed the request.',
              ),
              RequestRejection.signature);
        }
      }
    }

    // 4. Not a replay? (Only remembered for authentic requests.)
    if (!signatureOk) {
      checks.add(const ServerCheck.info('request.replay', 'Request id unused',
          'Not checked: the signature did not verify.'));
    } else if (replayCache
        .checkAndRemember('${key!.fingerprint}/${auth.requestId}')) {
      checks.add(ServerCheck.pass(
        'request.replay',
        'Request id unused',
        'Request id ${_short(auth.requestId)} not seen in the last '
            '${replayCache.window.inMinutes} min.',
      ));
    } else {
      fail(
          ServerCheck.fail(
            'request.replay',
            'Request id unused',
            'Request id ${_short(auth.requestId)} was already used: a '
                'captured request was replayed.',
          ),
          RequestRejection.replay);
    }
    return RequestVerification(checks, rejection);
  }

  static String _short(String id) =>
      id.length <= 10 ? id : '${id.substring(0, 10)}…';
}
