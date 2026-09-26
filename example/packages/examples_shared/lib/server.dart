/// Mock-server building blocks for the biometric_signature examples: an
/// in-process JSON transport with fault injection, single-use challenges,
/// a replay cache, key-value persistence, an audit log and a skewable
/// clock.
///
/// Demo code, not production code: a real server needs TLS, rate limits,
/// durable storage and attestation revocation checks.
library;

export 'src/platform/device_platform.dart';
export 'src/server/audit_log.dart';
export 'src/server/challenge_store.dart';
export 'src/server/clock.dart';
export 'src/server/key_value_store.dart';
export 'src/server/observable.dart';
export 'src/server/transport.dart';
