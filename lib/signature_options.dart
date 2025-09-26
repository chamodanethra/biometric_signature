/// Options that control how a signature request behaves on each platform.
class SignatureOptions {
  /// Creates a new [SignatureOptions] instance.
  const SignatureOptions({
    required this.payload,
    this.promptMessage,
    this.androidOptions,
    this.iosOptions,
  });

  /// Payload string that will be signed and returned in the response.
  final String payload;

  /// Custom prompt message shown in the biometric authentication dialog.
  final String? promptMessage;

  /// Platform-specific overrides for Android.
  final AndroidSignatureOptions? androidOptions;

  /// Platform-specific overrides for iOS.
  final IosSignatureOptions? iosOptions;

  /// Converts the options into a flat map that the method channel expects.
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

  /// Creates a [SignatureOptions] instance from the legacy plugin map API.
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

/// Android-specific overrides for a signature request.
class AndroidSignatureOptions {
  /// Creates a new [AndroidSignatureOptions] instance.
  const AndroidSignatureOptions({
    this.cancelButtonText,
    this.allowDeviceCredentials,
  });

  /// Text displayed on the cancel button in the biometric prompt.
  final String? cancelButtonText;

  /// Whether device credentials can satisfy the prompt.
  final bool? allowDeviceCredentials;

  /// Whether any Android-specific values have been provided.
  bool get hasValues =>
      cancelButtonText != null || allowDeviceCredentials != null;

  /// Converts Android-specific options to a method-channel friendly map.
  Map<String, dynamic> toMethodChannelMap() {
    return {
      if (cancelButtonText != null) 'cancelButtonText': cancelButtonText,
      if (allowDeviceCredentials != null)
        'allowDeviceCredentials': allowDeviceCredentials,
    };
  }
}

/// iOS-specific overrides for a signature request.
class IosSignatureOptions {
  /// Creates a new [IosSignatureOptions] instance.
  const IosSignatureOptions({this.shouldMigrate});

  /// Whether the legacy secure enclave key should be migrated if available.
  final bool? shouldMigrate;

  /// Whether any iOS-specific values have been provided.
  bool get hasValues => shouldMigrate != null;

  /// Converts iOS-specific options to a method-channel friendly map.
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
