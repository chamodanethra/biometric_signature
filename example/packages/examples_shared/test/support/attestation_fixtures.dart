import 'dart:typed_data';

import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';

import 'fixtures.dart';

/// A Google `android/keyattestation` test case: the chain plus the expected
/// key description JSON (when the case has one).
class AttestationFixture {
  AttestationFixture(this.path)
      : chain = certificatesFromPem(fixtureText('attestation/$path.pem'));

  /// Path below `test/fixtures/attestation/`, without extension.
  final String path;

  /// DER chain, leaf first.
  final List<Uint8List> chain;

  /// Expected KeyDescription JSON.
  Map<String, dynamic> get expected => fixtureJson('attestation/$path.json');

  /// The attested challenge recorded in the JSON.
  Uint8List get challenge => b64(expected['attestationChallenge']);

  /// Parsed certificates.
  List<X509Certificate> get certificates =>
      chain.map(X509Certificate.parse).toList();

  /// The leaf's public key as base64 SPKI (what `createKeys` returned).
  String get leafPublicKey => certificates.first.publicKey.base64;

  /// A clock inside every intermediate's validity window.
  DateTime get validAt {
    final certs = certificates;
    var start = certs.first.notBefore;
    var end = DateTime.utc(9999);
    for (var i = 1; i < certs.length - 1; i++) {
      if (certs[i].notBefore.isAfter(start)) start = certs[i].notBefore;
      if (certs[i].notAfter.isBefore(end)) end = certs[i].notAfter;
    }
    final at = start.add(const Duration(hours: 1));
    if (!at.isBefore(end)) {
      throw StateError('No common validity window for $path');
    }
    return at;
  }
}

/// Fixtures that carry an expected-values JSON file.
const List<String> fixturesWithJson = [
  'akita/sdk34/TEE_EC_NONE',
  'akita/sdk34/SB_RSA_NONE',
  'akita/sdk34/TEE_RSA_NONE_USERAUTH',
  'blueline/sdk28/SB_RSA_NONE_USERAUTH',
  'blueline/sdk28/TEE_EC_NONE',
  'walleye/sdk27/TEE_EC_NONE',
  'caiman/sdk36/SB_EC_RKP',
  'caiman/sdk36/TEE_EC_RKP',
  'frankel/sdk37/TEE_EC_2026',
  'tegu/sdk36/SB_EC_2026_ROOT',
  'tokay/sdk37/TEE_MLDSA_RKP',
];
