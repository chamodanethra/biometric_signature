class IosConfig {
  bool useDeviceCredentials;
  bool enforceBiometric;
  Map<String?, String?>? options;

  IosConfig({
    required this.useDeviceCredentials,
    this.enforceBiometric = false,
    this.options,
  });

  Map<String, dynamic> toMap() {
    return {
      'useDeviceCredentials': useDeviceCredentials,
      'enforceBiometric': enforceBiometric,
      'options': options,
    };
  }
}
