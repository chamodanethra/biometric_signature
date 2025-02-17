class IosConfig {
  bool useDeviceCredentials;
  bool enforceBiometric;

  IosConfig({
    required this.useDeviceCredentials,
    this.enforceBiometric = false,
  });

  Map<String, dynamic> toMap() {
    return {
      'useDeviceCredentials': useDeviceCredentials,
      'enforceBiometric': enforceBiometric,
    };
  }
}
