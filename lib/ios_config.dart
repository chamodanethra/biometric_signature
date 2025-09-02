enum IOSSignatureType {
  RSA,
  ECDSA,
}

extension IOSSignatureTypeExtension on IOSSignatureType {
  bool get isEc => this == IOSSignatureType.ECDSA;
}

class IosConfig {
  bool useDeviceCredentials;
  IOSSignatureType signatureType;

  IosConfig({
    required this.useDeviceCredentials,
    this.signatureType = IOSSignatureType.RSA,
  });
}
