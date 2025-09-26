class SignatureOptions {
  const SignatureOptions({
    required this.payload,
    this.promptMessage,
    this.androidOptions,
    this.iosOptions,
  });

  final String payload;
  final String? promptMessage;
  final AndroidSignatureOptions? androidOptions;
  final IosSignatureOptions? iosOptions;

  Map<String, dynamic> toMethodChannelMap() {
    final Map<String, dynamic> map = {
      'payload': payload,
      if (promptMessage != null) 'promptMessage': promptMessage,
    };

    if (androidOptions != null) {
      map.addAll(androidOptions!.toMethodChannelMap());
    }

    if (iosOptions != null) {
      map.addAll(iosOptions!.toMethodChannelMap());
    }

    return map;
  }

  factory SignatureOptions.fromLegacyMap(Map<String, String> legacy) {
    final String? payload = legacy['payload'];
    if (payload == null) {
      throw ArgumentError('`payload` is required to create SignatureOptions');
    }

    final android = AndroidSignatureOptions(
      cancelButtonText: legacy['cancelButtonText'],
      allowDeviceCredentials: _parseBool(legacy['allowDeviceCredentials']),
    );

    final ios = IosSignatureOptions(
      shouldMigrate: _parseBool(legacy['shouldMigrate']),
    );

    return SignatureOptions(
      payload: payload,
      promptMessage: legacy['promptMessage'],
      androidOptions: android.hasValues ? android : null,
      iosOptions: ios.hasValues ? ios : null,
    );
  }
}

class AndroidSignatureOptions {
  const AndroidSignatureOptions({
    this.cancelButtonText,
    this.allowDeviceCredentials,
  });

  final String? cancelButtonText;
  final bool? allowDeviceCredentials;

  bool get hasValues =>
      cancelButtonText != null || allowDeviceCredentials != null;

  Map<String, dynamic> toMethodChannelMap() {
    return {
      if (cancelButtonText != null) 'cancelButtonText': cancelButtonText,
      if (allowDeviceCredentials != null)
        'allowDeviceCredentials': allowDeviceCredentials,
    };
  }
}

class IosSignatureOptions {
  const IosSignatureOptions({this.shouldMigrate});

  final bool? shouldMigrate;

  bool get hasValues => shouldMigrate != null;

  Map<String, dynamic> toMethodChannelMap() {
    return {if (shouldMigrate != null) 'shouldMigrate': shouldMigrate};
  }
}

bool? _parseBool(String? value) {
  if (value == null) {
    return null;
  }
  switch (value.toLowerCase()) {
    case 'true':
      return true;
    case 'false':
      return false;
    default:
      return null;
  }
}
