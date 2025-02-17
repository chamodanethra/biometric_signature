class AndroidConfig {
  bool useDeviceCredentials;
  bool enforceBiometric;
  Map<String?, String?>? options;

  AndroidConfig({
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
