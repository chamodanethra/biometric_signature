import 'dart:convert';
import 'dart:typed_data';

import '../encoding/bytes.dart';
import 'clock.dart';

/// A challenge issued by [ChallengeStore.issue].
class IssuedChallenge {
  /// Creates a challenge.
  const IssuedChallenge({
    required this.id,
    required this.bytes,
    required this.purpose,
    required this.issuedAt,
    required this.expiresAt,
    this.boundTo,
  });

  /// Opaque identifier the client sends back.
  final String id;

  /// Random challenge bytes (e.g. the attestation challenge or login nonce).
  final Uint8List bytes;

  /// What the challenge may be used for, e.g. `register` or `login`.
  final String purpose;

  /// Optional binding (user id, device id, transaction id …).
  final String? boundTo;

  /// Issue time.
  final DateTime issuedAt;

  /// Expiry time.
  final DateTime expiresAt;

  /// [bytes] as base64.
  String get base64Value => base64.encode(bytes);

  /// JSON form for sending to the client.
  Map<String, dynamic> toJson() => {
        'challengeId': id,
        'challenge': base64Value,
        'purpose': purpose,
        if (boundTo != null) 'boundTo': boundTo,
        'expiresAt': expiresAt.toIso8601String(),
      };
}

/// Result of [ChallengeStore.consume] / [ChallengeStore.peek].
sealed class ChallengeResult {
  const ChallengeResult();

  /// Whether the challenge is usable.
  bool get isOk => this is ChallengeOk;

  /// A short reason for logs and error responses.
  String get reason;
}

/// The challenge is valid.
final class ChallengeOk extends ChallengeResult {
  /// Creates the result.
  const ChallengeOk(this.challenge);

  /// The challenge.
  final IssuedChallenge challenge;

  @override
  String get reason => 'ok';
}

/// No challenge with that id was issued (or it was purged).
final class ChallengeUnknown extends ChallengeResult {
  /// Creates the result.
  const ChallengeUnknown();

  @override
  String get reason => 'unknown challenge';
}

/// The challenge's TTL has passed.
final class ChallengeExpired extends ChallengeResult {
  /// Creates the result.
  const ChallengeExpired(this.challenge);

  /// The challenge.
  final IssuedChallenge challenge;

  @override
  String get reason => 'challenge expired';
}

/// The challenge was already used — a replay.
final class ChallengeAlreadyUsed extends ChallengeResult {
  /// Creates the result.
  const ChallengeAlreadyUsed(this.challenge);

  /// The challenge.
  final IssuedChallenge challenge;

  @override
  String get reason => 'challenge already used (replay)';
}

/// The challenge was issued for another purpose.
final class ChallengeWrongPurpose extends ChallengeResult {
  /// Creates the result.
  const ChallengeWrongPurpose(this.challenge, this.presentedPurpose);

  /// The challenge.
  final IssuedChallenge challenge;

  /// The purpose the caller asked for.
  final String presentedPurpose;

  @override
  String get reason =>
      'challenge issued for "${challenge.purpose}", not "$presentedPurpose"';
}

/// The challenge is bound to a different user/device/transaction.
final class ChallengeWrongBinding extends ChallengeResult {
  /// Creates the result.
  const ChallengeWrongBinding(this.challenge);

  /// The challenge.
  final IssuedChallenge challenge;

  @override
  String get reason => 'challenge bound to a different subject';
}

class _Entry {
  _Entry(this.challenge);

  final IssuedChallenge challenge;
  bool used = false;
}

/// In-memory, purpose-bound, single-use challenges with a TTL.
///
/// [consume] marks a challenge used the first time it is presented, even if
/// the caller's later verification fails: a failed attempt must not leave a
/// reusable challenge behind.
///
/// Documented exception — retrying an upload: for a registration whose
/// upload may be retried (the device already created the key), verify with
/// [peek] and call [markUsed] only once the registration succeeds. The
/// challenge then stays valid until its TTL.
class ChallengeStore {
  /// Creates a store using [clock] (defaults to the system clock).
  ChallengeStore({Clock? clock}) : clock = clock ?? Clock();

  /// Time source.
  final Clock clock;

  final Map<String, _Entry> _entries = {};

  /// Issues a random challenge of [length] bytes.
  IssuedChallenge issue({
    required String purpose,
    int length = 32,
    Duration ttl = const Duration(minutes: 2),
    String? boundTo,
  }) {
    purgeExpired();
    final now = clock.now();
    final challenge = IssuedChallenge(
      id: toHex(secureRandomBytes(16)),
      bytes: secureRandomBytes(length),
      purpose: purpose,
      boundTo: boundTo,
      issuedAt: now,
      expiresAt: now.add(ttl),
    );
    _entries[challenge.id] = _Entry(challenge);
    return challenge;
  }

  /// Validates and consumes the challenge [id].
  ///
  /// A challenge issued with `boundTo` must be presented with the same
  /// [boundTo]; an unbound challenge accepts any.
  ChallengeResult consume(String id,
      {required String purpose, String? boundTo}) {
    final result = peek(id, purpose: purpose, boundTo: boundTo);
    final entry = _entries[id];
    if (entry != null && result is! ChallengeExpired) entry.used = true;
    return result;
  }

  /// Validates the challenge [id] without consuming it.
  ChallengeResult peek(String id, {required String purpose, String? boundTo}) {
    final entry = _entries[id];
    if (entry == null) return const ChallengeUnknown();
    final c = entry.challenge;
    if (entry.used) return ChallengeAlreadyUsed(c);
    if (!clock.now().isBefore(c.expiresAt)) return ChallengeExpired(c);
    if (c.purpose != purpose) return ChallengeWrongPurpose(c, purpose);
    if (c.boundTo != null && c.boundTo != boundTo) {
      return ChallengeWrongBinding(c);
    }
    return ChallengeOk(c);
  }

  /// Marks [id] used (after a [peek]-verified operation succeeded).
  void markUsed(String id) => _entries[id]?.used = true;

  /// Number of challenges not yet used or expired.
  int get outstanding {
    final now = clock.now();
    return _entries.values
        .where((e) => !e.used && now.isBefore(e.challenge.expiresAt))
        .length;
  }

  /// Drops challenges that expired more than a minute ago. Used ones are
  /// kept until then so replays report [ChallengeAlreadyUsed].
  void purgeExpired() {
    final cutoff = clock.now().subtract(const Duration(minutes: 1));
    _entries.removeWhere((_, e) => e.challenge.expiresAt.isBefore(cutoff));
  }

  /// Forgets every challenge.
  void clear() => _entries.clear();
}

/// Remembers ids (request ids, nonces) for a window, to reject replays of
/// requests that carry their own nonce instead of a server challenge.
class ReplayCache {
  /// Creates a cache remembering ids for [window].
  ReplayCache({this.window = const Duration(minutes: 5), Clock? clock})
      : clock = clock ?? Clock();

  /// How long an id is remembered.
  final Duration window;

  /// Time source.
  final Clock clock;

  final Map<String, DateTime> _seen = {};

  /// Returns `true` and remembers [id] the first time; `false` for a replay.
  bool checkAndRemember(String id) {
    final now = clock.now();
    _seen.removeWhere((_, at) => now.difference(at) > window);
    if (_seen.containsKey(id)) return false;
    _seen[id] = now;
    return true;
  }

  /// Forgets every id.
  void clear() => _seen.clear();
}
