class AndroidConfig {
  bool useDeviceCredentials;
  AndroidSignatureType signatureType;

  AndroidConfig({
    required this.useDeviceCredentials,
    this.signatureType = AndroidSignatureType.RSA,
  });
}

enum AndroidSignatureType {
  RSA,
  ECDSA,
}

extension AndroidSignatureTypeExtension on AndroidSignatureType {
  bool get isEc => this == AndroidSignatureType.ECDSA;
}