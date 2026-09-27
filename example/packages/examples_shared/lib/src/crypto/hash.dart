import 'dart:typed_data';

import 'package:pointycastle/api.dart' show Digest;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';

/// Hash functions used by the verifiers and encryption helpers.
enum HashAlgorithm {
  /// SHA-1. Only used as OAEP's MGF1 digest on Android keystore keys.
  sha1('SHA-1', 20, '1.3.14.3.2.26'),

  /// SHA-256.
  sha256('SHA-256', 32, '2.16.840.1.101.3.4.2.1'),

  /// SHA-384.
  sha384('SHA-384', 48, '2.16.840.1.101.3.4.2.2'),

  /// SHA-512.
  sha512('SHA-512', 64, '2.16.840.1.101.3.4.2.3');

  const HashAlgorithm(this.label, this.lengthBytes, this.oid);

  /// Display name, e.g. `SHA-256`.
  final String label;

  /// Output length in bytes.
  final int lengthBytes;

  /// The digest's object identifier (used in PKCS#1 DigestInfo).
  final String oid;

  /// A fresh pointycastle digest instance.
  Digest createDigest() => switch (this) {
        HashAlgorithm.sha1 => SHA1Digest(),
        HashAlgorithm.sha256 => SHA256Digest(),
        HashAlgorithm.sha384 => SHA384Digest(),
        HashAlgorithm.sha512 => SHA512Digest(),
      };

  /// Hashes [data].
  Uint8List hash(List<int> data) =>
      createDigest().process(Uint8List.fromList(data));
}
