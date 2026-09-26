import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fixtures.dart';

void main() {
  test('source and fetch date are recorded', () {
    expect(googleRootsSourceUrl,
        'https://android.googleapis.com/attestation/root');
    expect(googleRootsFetchedOn, '2026-09-27');
  });

  test('each fingerprint is the SHA-256 of its PEM SPKI', () {
    expect(googleAttestationRoots, hasLength(2));
    for (final root in googleAttestationRoots) {
      final cert = X509Certificate.parse(certificatesFromPem(root.pem).single);
      expect(toHex(cert.spkiSha256), root.spkiSha256, reason: root.name);
      expect(cert.isSelfIssued, isTrue);
      expect(cert.verifySignedBy(cert.publicKey).isValid, isTrue);
    }
    expect(googleRootSpkiSha256, {
      for (final r in googleAttestationRoots) r.spkiSha256,
    });
  });

  test('covers the RSA-4096 root and the ECDSA P-384 root', () {
    final keys = [
      for (final root in googleAttestationRoots)
        X509Certificate.parse(certificatesFromPem(root.pem).single)
            .publicKey
            .description,
    ];
    expect(keys, containsAll(['RSA 4096', 'EC P-384']));
  });

  test('software attestation root fingerprints match the AOSP roots', () {
    final certs = X509Certificate.parsePemChain(
        fixtureText('attestation/software_roots.pem'));
    expect({for (final c in certs) toHex(c.spkiSha256)},
        androidSoftwareRootSpkiSha256);
    expect(androidSoftwareRootSpkiSha256.intersection(googleRootSpkiSha256),
        isEmpty);
  });
}
