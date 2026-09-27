import 'dart:convert';

import 'package:banking_app_example/client/bank_client.dart';
import 'package:banking_app_example/server/models.dart';
import 'package:banking_app_example/server/request_signing.dart';
import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/biometric_signature_platform_interface.dart'
    show BiometricSignaturePlatform;
import 'package:examples_shared/server.dart';
import 'package:examples_shared/testing.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late SoftwareBiometricPlatform fake;
  late ManualClock clock;
  late Clock deviceClock;
  late RequestVerifier verifier;
  late String publicKey;
  final api = BiometricSignature();
  const route = BankRoutes.prepare;
  final body = <String, dynamic>{
    'fromAccount': 'CHK-4821',
    'payeeId': 'p-alice',
    'amountCents': 125000,
    'currency': 'USD',
  };

  setUp(() async {
    fake = SoftwareBiometricPlatform();
    BiometricSignaturePlatform.instance = fake;
    clock = ManualClock(DateTime.utc(2026, 9, 27, 12));
    deviceClock = Clock(source: clock.now);
    verifier = RequestVerifier(clock: clock);
    final created = await api.createKeys(
      keyAlias: KeyAliases.deviceBinding,
      config: CreateKeysConfig(
        signatureType: SignatureType.ecdsa,
        requireAuthentication: false,
        failIfExists: true,
      ),
    );
    publicKey = created.publicKey!;
  });

  Future<Map<String, dynamic>> signed(
          [Map<String, dynamic>? payload,
          BankRoute signedRoute = route]) async =>
      (await signRequest(
        api: api,
        clock: deviceClock,
        route: signedRoute,
        body: payload ?? body,
        deviceId: 'dev-1',
      ))
          .envelope;

  /// A JSON round trip, as the mock transport does.
  Map<String, dynamic> wire(Map<String, dynamic> envelope) =>
      jsonDecode(jsonEncode(envelope)) as Map<String, dynamic>;

  RequestVerification verify(Map<String, dynamic> envelope,
          {String? key, BankRoute at = route}) =>
      verifier.verify(
          route: at,
          envelope: wire(envelope),
          publicKey: key ?? publicKey,
          keyProblem: 'Unknown device dev-1');

  test('the canonical string is METHOD, PATH, TIMESTAMP, sha256(body), id', () {
    expect(
      canonicalRequest(
          method: 'POST',
          path: '/transfers/prepare',
          timestampMs: 1790000000000,
          bodySha256: 'abc',
          requestId: 'r1'),
      'POST\n/transfers/prepare\n1790000000000\nabc\nr1',
    );
    // Canonical JSON: key order does not change the digest.
    expect(bodyDigest({'b': 1, 'a': 2}), bodyDigest({'a': 2, 'b': 1}));
    expect(bodyDigest({'a': 2}), isNot(bodyDigest({'a': 3})));
  });

  test('signs silently with createSignature and verifies', () async {
    final envelope = await signed();
    final call = fake.calls.lastWhere((c) => c.method == 'createSignature');
    expect(call.keyAlias, KeyAliases.deviceBinding);
    expect(call.arguments['payload'], contains('POST\n/transfers/prepare\n'));
    final result = verify(envelope);
    expect(result.ok, isTrue, reason: result.reason);
    expect(result.checks.map((c) => c.id), [
      'request.device',
      'request.timestamp',
      'request.signature',
      'request.replay',
    ]);
  });

  group('clock skew (±60 s)', () {
    test('59 s off is accepted', () async {
      deviceClock.skew = const Duration(seconds: 59);
      expect(verify(await signed()).ok, isTrue);
    });

    test('61 s ahead is rejected', () async {
      deviceClock.skew = const Duration(seconds: 61);
      final result = verify(await signed());
      expect(result.rejection, RequestRejection.timestamp);
      expect(result.reason, contains('+61.0 s'));
    });

    test('a request delivered 90 s late is rejected', () async {
      final envelope = await signed();
      clock.advance(const Duration(seconds: 90));
      expect(verify(envelope).rejection, RequestRejection.timestamp);
    });

    test('the window follows the policy', () async {
      verifier.maxSkew = const Duration(minutes: 5);
      deviceClock.skew = const Duration(seconds: 90);
      expect(verify(await signed()).ok, isTrue);
    });
  });

  test('a replayed request id is rejected', () async {
    final envelope = await signed();
    expect(verify(envelope).ok, isTrue);
    final replay = verify(envelope);
    expect(replay.rejection, RequestRejection.replay);
    expect(replay.checks.singleWhere((c) => c.id == 'request.signature').failed,
        isFalse);
  });

  test('ids are only remembered for authentic requests', () async {
    final envelope = await signed();
    final forged = wire(envelope);
    (forged['body'] as Map<String, dynamic>)['amountCents'] = 1;
    expect(verify(forged).rejection, RequestRejection.signature);
    expect(verify(envelope).ok, isTrue);
  });

  group('tampering', () {
    test('changing the body breaks the signature', () async {
      final envelope = wire(await signed());
      (envelope['body'] as Map<String, dynamic>)['amountCents'] = 1025000;
      final result = verify(envelope);
      expect(result.rejection, RequestRejection.signature);
      expect(result.reason, contains('Signature mismatch'));
    });

    test('replaying a body on another route breaks the signature', () async {
      final envelope = await signed();
      expect(verify(envelope, at: BankRoutes.confirm).rejection,
          RequestRejection.signature);
    });

    test('changing the timestamp breaks the signature', () async {
      final envelope = wire(await signed());
      final auth = envelope['auth'] as Map<String, dynamic>;
      auth['timestamp'] = (auth['timestamp'] as int) + 1000;
      expect(verify(envelope).rejection, RequestRejection.signature);
    });

    test('a decimal in the body is not canonical', () async {
      final envelope = wire(await signed());
      (envelope['body'] as Map<String, dynamic>)['amountCents'] = 1250.5;
      final result = verify(envelope);
      expect(result.rejection, RequestRejection.signature);
      expect(result.reason, contains('not canonical JSON'));
    });
  });

  test('another key does not verify', () async {
    final other = await api.createKeys(
      keyAlias: 'other',
      config: CreateKeysConfig(
          signatureType: SignatureType.ecdsa, requireAuthentication: false),
    );
    expect(verify(await signed(), key: other.publicKey).rejection,
        RequestRejection.signature);
  });

  test('an unknown device is rejected', () async {
    final result = verifier.verify(
        route: route,
        envelope: wire(await signed()),
        publicKey: null,
        keyProblem: 'Unknown device dev-1: not bound to this bank.');
    expect(result.rejection, RequestRejection.device);
    expect(result.reason, contains('Unknown device'));
  });

  test('a malformed envelope is rejected', () {
    final result = verifier.verify(
        route: route, envelope: {'body': body}, publicKey: publicKey);
    expect(result.rejection, RequestRejection.malformed);
  });

  test('a missing device key surfaces as a signing error', () async {
    final client = BankClient(
        api: api,
        transport: MockTransport(latency: Duration.zero),
        clock: deviceClock)
      ..deviceId = 'dev-1';
    await api.deleteKeys(keyAlias: KeyAliases.deviceBinding);
    await expectLater(
      client.fetchAccounts(),
      throwsA(isA<BankError>()
          .having((e) => e.kind, 'kind', BankErrorKind.signing)
          .having((e) => e.code, 'code', BiometricError.keyNotFound)),
    );
    expect(
        client.requestLog.entries.single.status, RequestStatus.signingFailed);
  });
}
