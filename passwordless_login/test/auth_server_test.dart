import 'dart:convert';
import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/biometric_signature_platform_interface.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/testing.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:passwordless_login_example/server/auth_server.dart';
import 'package:passwordless_login_example/server/models.dart';
import 'package:passwordless_login_example/server/policy.dart';

void main() {
  final original = BiometricSignaturePlatform.instance;
  late SoftwareBiometricPlatform fake;
  late BiometricSignature api;
  late ManualClock clock;
  late MockTransport transport;
  late InMemoryKeyValueStore store;
  late AuthServer server;

  AuthServer newServer({Set<String>? roots}) => AuthServer(
        store: store,
        transport: transport,
        clock: clock,
        trustedRootSpkiSha256: roots ?? {fake.syntheticRootSpkiSha256},
        verifyInIsolate: false,
      );

  setUp(() {
    fake = SoftwareBiometricPlatform(attestedPackageName: attestedPackageName);
    BiometricSignaturePlatform.instance = fake;
    api = BiometricSignature();
    clock = ManualClock(DateTime.utc(2026, 9, 27, 12));
    transport = MockTransport(latency: Duration.zero, clock: clock);
    store = InMemoryKeyValueStore();
    server = newServer();
  });

  tearDown(() => BiometricSignaturePlatform.instance = original);

  Future<Map<String, dynamic>> registerBegin(String username,
          {DevicePlatform platform = DevicePlatform.android}) =>
      transport.call(ApiRoutes.registerBegin,
          {'username': username, 'platform': platform.name});

  Future<KeyCreationResult> createKey(String alias, Uint8List? challenge) =>
      api.createKeys(
        keyAlias: alias,
        config: CreateKeysConfig(
          signatureType: SignatureType.ecdsa,
          enforceBiometric: true,
          failIfExists: true,
          attestationChallenge: challenge,
        ),
      );

  Map<String, dynamic> finishBody(
    String username,
    String alias,
    String challengeId,
    String publicKey,
    List<Uint8List>? chain, {
    DevicePlatform platform = DevicePlatform.android,
  }) =>
      {
        'username': username,
        'challengeId': challengeId,
        'alias': alias,
        'platform': platform.name,
        'publicKey': publicKey,
        'attestationChain':
            chain == null ? null : [for (final c in chain) base64.encode(c)],
        'authenticationType': 'biometric',
        'allowDeviceCredentials': false,
        'invalidateOnEnrollment': true,
      };

  /// Registers [username] under alias `acct_<username>`.
  Future<Map<String, dynamic>> register(String username,
      {DevicePlatform platform = DevicePlatform.android}) async {
    fake.simulatedPlatform = platform;
    final begin = await registerBegin(username, platform: platform);
    expect(begin['ok'], isTrue, reason: '$begin');
    final alias = 'acct_$username';
    final key = await createKey(
      alias,
      platform == DevicePlatform.android
          ? base64.decode(begin['challenge'] as String)
          : null,
    );
    expect(key.code, BiometricError.success);
    return transport.call(
      ApiRoutes.registerFinish,
      finishBody(username, alias, begin['challengeId'] as String,
          key.publicKey!, key.attestationCertificateChain,
          platform: platform),
    );
  }

  /// Runs a login for [username]. The overrides simulate attacks.
  Future<Map<String, dynamic>> login(
    String username, {
    String? signWithAlias,
    String? presentUserId,
    String? presentDeviceKeyId,
    Duration waitBeforeFinish = Duration.zero,
  }) async {
    final begin =
        await transport.call(ApiRoutes.loginBegin, {'username': username});
    expect(begin['ok'], isTrue, reason: '$begin');
    final payload = signedChallengePayload(
      purpose: Purposes.login,
      rp: begin['rp'] as String,
      userId: begin['userId'] as String,
      challengeId: begin['challengeId'] as String,
      nonceBase64: begin['nonce'] as String,
    );
    final device = (begin['devices'] as List).first as Map<String, dynamic>;
    final signed = await api.createSignatureFromBytes(
      payload: payload,
      keyAlias: signWithAlias ?? device['alias'] as String,
    );
    expect(signed.code, BiometricError.success);
    clock.advance(waitBeforeFinish);
    return transport.call(ApiRoutes.loginFinish, {
      'userId': presentUserId ?? begin['userId'],
      'deviceKeyId': presentDeviceKeyId ?? device['deviceKeyId'],
      'challengeId': begin['challengeId'],
      'signature': signed.signature,
      'authenticationType': signed.authenticationType?.name,
    });
  }

  group('registration', () {
    test('verifies the attestation and stores a TEE-tier key', () async {
      final r = await register('alice');
      expect(r['ok'], isTrue, reason: '$r');
      expect(r['trustTier'], TrustTier.tee.name);
      final report =
          AttestationReport.fromJson(r['report'] as Map<String, dynamic>);
      expect(report.passed, isTrue, reason: report.failures.join('\n'));
      expect(report.check(AttestationCheckIds.revocation)?.status,
          CheckStatus.warn);
      final code = r['recoveryCode'] as String;
      expect(code, matches(RegExp(r'^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$')));

      final device = server.deviceKey(r['deviceKeyId'] as String)!;
      expect(device.algorithm, SignatureAlgorithm.ecdsaSha256);
      expect(device.alias, 'acct_alice');
      expect(device.isActive, isTrue);
      // Only a salted hash of the recovery code is stored.
      final user = server.user(r['userId'] as String)!;
      expect(jsonEncode(user.toJson()), isNot(contains(code)));
      expect(user.recoveryCodeHash, hashRecoveryCode(user.recoverySalt, code));
    });

    test('rejects a chain made for a different challenge', () async {
      final begin = await registerBegin('alice');
      final key = await createKey('acct_alice', secureRandomBytes(32));
      final r = await transport.call(
        ApiRoutes.registerFinish,
        finishBody('alice', 'acct_alice', begin['challengeId'] as String,
            key.publicKey!, key.attestationCertificateChain),
      );
      expect(r['ok'], isFalse);
      expect(r['error'], ServerErrors.attestationFailed);
      final report =
          AttestationReport.fromJson(r['report'] as Map<String, dynamic>);
      expect(report.check(AttestationCheckIds.challenge)?.status,
          CheckStatus.fail);
      expect(server.users, isEmpty);
    });

    test('rejects a challenge bound to another username', () async {
      final begin = await registerBegin('alice');
      final key = await createKey(
          'acct_mallory', base64.decode(begin['challenge'] as String));
      final r = await transport.call(
        ApiRoutes.registerFinish,
        finishBody('mallory', 'acct_mallory', begin['challengeId'] as String,
            key.publicKey!, key.attestationCertificateChain),
      );
      expect(r['error'], ServerErrors.challenge);
      expect(r['reason'], contains('different subject'));
    });

    test('rejects a chain that does not end at a trusted root', () async {
      server = newServer(roots: const {}); // e.g. Google roots only
      final r = await register('alice');
      expect(r['ok'], isFalse);
      expect(r['error'], ServerErrors.attestationFailed);
      final report =
          AttestationReport.fromJson(r['report'] as Map<String, dynamic>);
      expect(report.check(AttestationCheckIds.chainRoot)?.status,
          CheckStatus.fail);
    });

    test('rejects a key attested for another app package', () async {
      fake.attestedPackageName = 'com.evil.clone';
      final r = await register('alice');
      expect(r['error'], ServerErrors.attestationFailed);
      final report =
          AttestationReport.fromJson(r['report'] as Map<String, dynamic>);
      expect(report.check(AttestationCheckIds.application)?.status,
          CheckStatus.fail);
    });

    test('rejects a public key that is already registered', () async {
      await register('alice');
      final begin = await registerBegin('bob');
      final alice = await api.getKeyInfo(keyAlias: 'acct_alice');
      final r = await transport.call(
        ApiRoutes.registerFinish,
        finishBody('bob', 'acct_alice', begin['challengeId'] as String,
            alice.publicKey!, null),
      );
      expect(r['ok'], isFalse);
      // Attestation is required and missing, or the key is reused: either
      // way it is refused.
      expect(r['error'],
          anyOf(ServerErrors.keyReused, ServerErrors.attestationRequired));
    });

    test('policy rejects non-Android devices while attestation is required',
        () async {
      final begin = await registerBegin('alice', platform: DevicePlatform.ios);
      expect(begin['ok'], isFalse);
      expect(begin['error'], ServerErrors.attestationRequired);
      expect(begin['reason'], contains('Require attestation'));

      // A client lying about its platform still has to send a chain.
      fake.simulatedPlatform = DevicePlatform.ios;
      final androidBegin = await registerBegin('alice');
      final key = await createKey('acct_alice', null);
      final r = await transport.call(
        ApiRoutes.registerFinish,
        finishBody('alice', 'acct_alice', androidBegin['challengeId'] as String,
            key.publicKey!, null),
      );
      expect(r['error'], ServerErrors.attestationRequired);
      expect(server.users, isEmpty);
    });

    test('allows unattested devices when attestation is optional', () async {
      await server
          .updatePolicy(server.policy.copyWith(requireAttestation: false));
      final r = await register('alice', platform: DevicePlatform.ios);
      expect(r['ok'], isTrue, reason: '$r');
      expect(r['trustTier'], TrustTier.none.name);
      expect((await login('alice'))['ok'], isTrue);
    });

    test('a failed chain is "untrusted" when attestation is optional',
        () async {
      server = newServer(roots: const {});
      await server
          .updatePolicy(server.policy.copyWith(requireAttestation: false));
      final r = await register('alice');
      expect(r['ok'], isTrue, reason: '$r');
      expect(r['trustTier'], TrustTier.untrusted.name);
    });

    test('Windows registers an RSA key and signs with PKCS#1 v1.5', () async {
      await server
          .updatePolicy(server.policy.copyWith(requireAttestation: false));
      final r = await register('alice', platform: DevicePlatform.windows);
      expect(r['ok'], isTrue, reason: '$r');
      final device = server.deviceKey(r['deviceKeyId'] as String)!;
      expect(device.algorithm, SignatureAlgorithm.rsaPkcs1Sha256);
      expect((await login('alice'))['ok'], isTrue);
    });

    test(
        'a failed upload can be retried with the same challenge until it '
        'succeeds; then the challenge is spent', () async {
      final begin = await registerBegin('carol');
      final challengeId = begin['challengeId'] as String;
      final key = await createKey(
          'acct_carol', base64.decode(begin['challenge'] as String));

      transport.failNext(ApiRoutes.registerFinish);
      await expectLater(
        transport.call(
          ApiRoutes.registerFinish,
          finishBody('carol', 'acct_carol', challengeId, key.publicKey!,
              key.attestationCertificateChain),
        ),
        throwsA(isA<TransportException>()),
      );
      expect(
          server.challenges
              .peek(challengeId, purpose: Purposes.register, boundTo: 'carol'),
          isA<ChallengeOk>());

      // The client reads the key and chain back from the device.
      final info = await api.getKeyInfo(keyAlias: 'acct_carol');
      clock.advance(const Duration(minutes: 3)); // still within the TTL
      final r = await transport.call(
        ApiRoutes.registerFinish,
        finishBody('carol', 'acct_carol', challengeId, info.publicKey!,
            info.attestationCertificateChain),
      );
      expect(r['ok'], isTrue, reason: '$r');
      expect(
          server.challenges
              .peek(challengeId, purpose: Purposes.register, boundTo: 'carol'),
          isA<ChallengeAlreadyUsed>());

      final replay = await transport.replayLast(ApiRoutes.registerFinish);
      expect(replay['ok'], isFalse);
      expect(replay['reason'], contains('already used'));
    });

    test('an upload after the challenge TTL is rejected', () async {
      final begin = await registerBegin('carol');
      final key = await createKey(
          'acct_carol', base64.decode(begin['challenge'] as String));
      clock.advance(server.policy.registrationChallengeTtl);
      final r = await transport.call(
        ApiRoutes.registerFinish,
        finishBody('carol', 'acct_carol', begin['challengeId'] as String,
            key.publicKey!, key.attestationCertificateChain),
      );
      expect(r['reason'], contains('expired'));
    });
  });

  group('login', () {
    test('accepts a signature over the server-rebuilt payload', () async {
      final reg = await register('alice');
      final r = await login('alice');
      expect(r['ok'], isTrue, reason: '$r');
      final session =
          SessionRecord.fromJson(r['session'] as Map<String, dynamic>);
      expect(session.userId, reg['userId']);
      expect(session.trustTier, TrustTier.tee);
      final checks = [
        for (final c in r['checks'] as List)
          AttestationCheck.fromJson(c as Map<String, dynamic>),
      ];
      expect(checks.where((c) => c.status == CheckStatus.fail), isEmpty);
      final device = server.deviceKey(reg['deviceKeyId'] as String)!;
      expect(device.loginCount, 1);
      expect(device.lastAuthenticationType, 'biometric');
      expect(
        server.audit.entries.last.detail,
        contains('client-reported'),
      );
    });

    test('a replayed login is rejected: the nonce was consumed', () async {
      await register('alice');
      expect((await login('alice'))['ok'], isTrue);
      final replay = await transport.replayLast(ApiRoutes.loginFinish);
      expect(replay['ok'], isFalse);
      expect(replay['error'], ServerErrors.challenge);
      expect(replay['reason'], contains('already used'));
    });

    test('an expired nonce is rejected', () async {
      await register('alice');
      final r = await login('alice',
          waitBeforeFinish:
              server.policy.loginNonceTtl + const Duration(seconds: 1));
      expect(r['ok'], isFalse);
      expect(r['reason'], contains('expired'));
    });

    test('the clock-jump fault expires the next nonce', () async {
      await register('alice');
      server.jumpClockBeforeNext(
          ApiRoutes.loginFinish, const Duration(minutes: 5));
      final r = await login('alice');
      expect(r['reason'], contains('expired'));
      expect(clock.skew, const Duration(minutes: 5));
      expect((await login('alice'))['ok'], isTrue);
    });

    test('a nonce issued to one user is rejected for another', () async {
      await register('alice');
      final bob = await register('bob');
      // Alice's nonce, presented as Bob with Bob's key.
      final r = await login('alice',
          signWithAlias: 'acct_bob',
          presentUserId: bob['userId'] as String,
          presentDeviceKeyId: bob['deviceKeyId'] as String);
      expect(r['ok'], isFalse);
      expect(r['reason'], contains('different subject'));
    });

    test('a signature by another key is rejected', () async {
      await register('alice');
      await register('bob');
      final r = await login('alice', signWithAlias: 'acct_bob');
      expect(r['ok'], isFalse);
      expect(r['error'], ServerErrors.badSignature);
    });

    test('a signature tampered with in transit is rejected', () async {
      await register('alice');
      transport.tamper(ApiRoutes.loginFinish, 'signature', (v) {
        final bytes = base64.decode(v! as String);
        bytes[bytes.length - 1] ^= 0x01;
        return base64.encode(bytes);
      });
      final r = await login('alice');
      expect(r['ok'], isFalse);
      expect(r['error'], ServerErrors.badSignature);
    });

    test('a login signature cannot be used to unbind the device', () async {
      final reg = await register('alice');
      final begin =
          await transport.call(ApiRoutes.loginBegin, {'username': 'alice'});
      final r = await transport.call(ApiRoutes.unbindFinish, {
        'userId': reg['userId'],
        'deviceKeyId': reg['deviceKeyId'],
        'challengeId': begin['challengeId'],
        'signature': 'AAAA',
      });
      expect(r['ok'], isFalse);
      expect(r['reason'], contains('not "unbind"'));
      expect(server.deviceKey(reg['deviceKeyId'] as String)!.isActive, isTrue);
    });
  });

  group('recovery and unbinding', () {
    test('the recovery code binds a new key and retires the old one', () async {
      final reg = await register('alice');
      final code = reg['recoveryCode'] as String;

      final wrong = await transport.call(ApiRoutes.recoveryBegin, {
        'username': 'alice',
        'recoveryCode': 'AAAA-BBBB-CCCC',
        'platform': 'android'
      });
      expect(wrong['error'], ServerErrors.badRecoveryCode);

      final begin = await transport.call(ApiRoutes.recoveryBegin, {
        'username': 'alice',
        'recoveryCode': code.toLowerCase(), // normalized by the server
        'platform': 'android',
      });
      expect(begin['ok'], isTrue, reason: '$begin');
      final key = await createKey(
          'acct_alice2', base64.decode(begin['challenge'] as String));
      final r = await transport.call(ApiRoutes.recoveryFinish, {
        ...finishBody('alice', 'acct_alice2', begin['challengeId'] as String,
            key.publicKey!, key.attestationCertificateChain),
        'recoveryCode': code,
      });
      expect(r['ok'], isTrue, reason: '$r');
      expect(r['userId'], reg['userId']);
      expect(r['superseded'], [reg['deviceKeyId']]);
      expect(r['recoveryCode'], isNot(code));
      final old = server.deviceKey(reg['deviceKeyId'] as String)!;
      expect(old.status, DeviceKeyStatus.superseded);
      expect(old.supersededBy, r['deviceKeyId']);

      // The old key can no longer sign in; the new one can.
      final stale = await login('alice',
          signWithAlias: 'acct_alice',
          presentDeviceKeyId: reg['deviceKeyId'] as String);
      expect(stale['error'], ServerErrors.deviceInactive);
      expect((await login('alice'))['ok'], isTrue);

      // The old code is spent.
      final again = await transport.call(ApiRoutes.recoveryBegin,
          {'username': 'alice', 'recoveryCode': code, 'platform': 'android'});
      expect(again['error'], ServerErrors.badRecoveryCode);
    });

    test('a signed unbind retires the key', () async {
      final reg = await register('alice');
      final begin = await transport.call(ApiRoutes.unbindBegin,
          {'userId': reg['userId'], 'deviceKeyId': reg['deviceKeyId']});
      final payload = signedChallengePayload(
        purpose: Purposes.unbind,
        rp: begin['rp'] as String,
        userId: reg['userId'] as String,
        challengeId: begin['challengeId'] as String,
        nonceBase64: begin['nonce'] as String,
      );
      final signed = await api.createSignatureFromBytes(
          payload: payload, keyAlias: 'acct_alice');
      final r = await transport.call(ApiRoutes.unbindFinish, {
        'userId': reg['userId'],
        'deviceKeyId': reg['deviceKeyId'],
        'challengeId': begin['challengeId'],
        'signature': signed.signature,
      });
      expect(r['ok'], isTrue, reason: '$r');
      expect(server.deviceKey(reg['deviceKeyId'] as String)!.status,
          DeviceKeyStatus.unbound);
      final next =
          await transport.call(ApiRoutes.loginBegin, {'username': 'alice'});
      expect(next['error'], ServerErrors.deviceInactive);
    });
  });

  test('records and policy persist across restarts', () async {
    await server.updatePolicy(server.policy
        .copyWith(requireAttestation: false, requireLockedBootloader: true));
    final reg = await register('alice');
    final restarted = newServer();
    await restarted.load();
    expect(restarted.users.single.username, 'alice');
    expect(restarted.deviceKey(reg['deviceKeyId'] as String)!.trustTier,
        TrustTier.tee);
    expect(restarted.policy.requireAttestation, isFalse);
    expect(restarted.policy.requireLockedBootloader, isTrue);
    expect(restarted.audit.entries, isNotEmpty);

    await restarted.reset();
    expect(restarted.users, isEmpty);
    expect(restarted.policy.requireAttestation, isTrue);
    expect(await store.keys(), ['audit_log']);
  });
}
