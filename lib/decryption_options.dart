/// Options that control how a decryption request behaves on each platform.
class DecryptionOptions {
  /// Creates a new [DecryptionOptions] instance.
  const DecryptionOptions({
    required this.payload,
    this.promptMessage,
    this.androidOptions,
    this.iosOptions,
  });

  /// The encrypted payload string (Base64 encoded) to be decrypted.
  final String payload;

  /// Custom prompt message shown in the biometric authentication dialog.
  final String? promptMessage;

  /// Platform-specific overrides for Android.
  final AndroidDecryptionOptions? androidOptions;

  /// Platform-specific overrides for iOS.
  final IosDecryptionOptions? iosOptions;

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
}

/// Android-specific overrides for a decryption request.
class AndroidDecryptionOptions {
  /// Creates a new [AndroidDecryptionOptions] instance.
  const AndroidDecryptionOptions({
    this.cancelButtonText,
    this.allowDeviceCredentials,
    this.subtitle,
  });

  /// Text displayed on the cancel button in the biometric prompt.
  final String? cancelButtonText;

  /// Whether device credentials can satisfy the prompt.
  final bool? allowDeviceCredentials;

  /// Optional subtitle shown underneath the title on Android's biometric prompt.
  final String? subtitle;

  /// Converts Android-specific options to a method-channel friendly map.
  Map<String, dynamic> toMethodChannelMap() {
    return {
      if (cancelButtonText != null) 'cancelButtonText': cancelButtonText,
      if (allowDeviceCredentials != null)
        'allowDeviceCredentials': allowDeviceCredentials,
      if (subtitle != null) 'subtitle': subtitle,
    };
  }
}

/// iOS-specific overrides for a decryption request.
class IosDecryptionOptions {
  /// Creates a new [IosDecryptionOptions] instance.
  const IosDecryptionOptions({this.shouldMigrate});

  /// Whether the legacy keychain key should be migrated if available.
  final bool? shouldMigrate;

  /// Converts iOS-specific options to a method-channel friendly map.
  Map<String, dynamic> toMethodChannelMap() {
    return {if (shouldMigrate != null) 'shouldMigrate': shouldMigrate};
  }
}
