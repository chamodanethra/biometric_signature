import 'package:examples_shared/server.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late ManualClock clock;
  late ChallengeStore store;

  setUp(() {
    clock = ManualClock(DateTime.utc(2026, 1, 1));
    store = ChallengeStore(clock: clock);
  });

  test('issues random, purpose-bound challenges', () {
    final a = store.issue(purpose: 'login');
    final b = store.issue(purpose: 'login', length: 16);
    expect(a.bytes, hasLength(32));
    expect(b.bytes, hasLength(16));
    expect(a.id, isNot(b.id));
    expect(a.bytes, isNot(b.bytes));
    expect(a.expiresAt, clock.now().add(const Duration(minutes: 2)));
    expect(a.toJson()['challenge'], a.base64Value);
    expect(store.outstanding, 2);
  });

  test('single use: the second consume is a replay', () {
    final c = store.issue(purpose: 'login');
    expect(store.consume(c.id, purpose: 'login'), isA<ChallengeOk>());
    expect(store.consume(c.id, purpose: 'login'), isA<ChallengeAlreadyUsed>());
    expect(store.outstanding, 0);
  });

  test('consumed on first presentation even when the purpose is wrong', () {
    final c = store.issue(purpose: 'register');
    expect(store.consume(c.id, purpose: 'login'), isA<ChallengeWrongPurpose>());
    expect(
        store.consume(c.id, purpose: 'register'), isA<ChallengeAlreadyUsed>());
  });

  test('expiry', () {
    final c = store.issue(purpose: 'login', ttl: const Duration(seconds: 30));
    clock.advance(const Duration(seconds: 30));
    final result = store.consume(c.id, purpose: 'login');
    expect(result, isA<ChallengeExpired>());
    expect(result.isOk, isFalse);
    expect(result.reason, contains('expired'));
  });

  test('binding', () {
    final c = store.issue(purpose: 'login', boundTo: 'alice');
    expect(store.peek(c.id, purpose: 'login', boundTo: 'bob'),
        isA<ChallengeWrongBinding>());
    expect(store.peek(c.id, purpose: 'login'), isA<ChallengeWrongBinding>());
    expect(store.consume(c.id, purpose: 'login', boundTo: 'alice'),
        isA<ChallengeOk>());
    final unbound = store.issue(purpose: 'login');
    expect(store.consume(unbound.id, purpose: 'login', boundTo: 'anyone'),
        isA<ChallengeOk>());
  });

  test('unknown ids', () {
    expect(store.consume('nope', purpose: 'login'), isA<ChallengeUnknown>());
  });

  test('peek + markUsed supports the registration-retry exception', () {
    final c = store.issue(purpose: 'register');
    // First upload fails after verification: the challenge stays valid.
    expect(store.peek(c.id, purpose: 'register'), isA<ChallengeOk>());
    expect(store.peek(c.id, purpose: 'register'), isA<ChallengeOk>());
    // Retry succeeds, then the challenge is burned.
    store.markUsed(c.id);
    expect(store.peek(c.id, purpose: 'register'), isA<ChallengeAlreadyUsed>());
  });

  test('used challenges are remembered until well after expiry', () {
    final c = store.issue(purpose: 'login', ttl: const Duration(seconds: 10));
    store.consume(c.id, purpose: 'login');
    clock.advance(const Duration(seconds: 20));
    store.purgeExpired();
    expect(store.consume(c.id, purpose: 'login'), isA<ChallengeAlreadyUsed>());
    clock.advance(const Duration(minutes: 2));
    store.purgeExpired();
    expect(store.consume(c.id, purpose: 'login'), isA<ChallengeUnknown>());
  });

  test('ReplayCache', () {
    final cache =
        ReplayCache(window: const Duration(seconds: 60), clock: clock);
    expect(cache.checkAndRemember('req-1'), isTrue);
    expect(cache.checkAndRemember('req-1'), isFalse);
    clock.advance(const Duration(seconds: 61));
    expect(cache.checkAndRemember('req-1'), isTrue);
  });

  test('clock skew', () {
    final c = Clock(source: () => DateTime.utc(2026));
    c.skew = const Duration(minutes: 5);
    expect(c.now(), DateTime.utc(2026, 1, 1, 0, 5));
  });
}
