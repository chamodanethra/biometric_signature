import 'package:flutter/foundation.dart';

import 'device_platform.dart';

/// Overrides [currentDevicePlatform] (e.g. in widget tests to render the
/// Windows or iOS variant of a screen). Reset to `null` in `tearDown`.
DevicePlatform? debugDevicePlatformOverride;

/// The platform the app runs on, from `defaultTargetPlatform` (which
/// `debugDefaultTargetPlatformOverride` also affects).
DevicePlatform currentDevicePlatform() {
  final override = debugDevicePlatformOverride;
  if (override != null) return override;
  if (kIsWeb) return DevicePlatform.other;
  return devicePlatformFor(defaultTargetPlatform);
}

/// Maps a Flutter [TargetPlatform] to a [DevicePlatform].
DevicePlatform devicePlatformFor(TargetPlatform platform) => switch (platform) {
      TargetPlatform.android => DevicePlatform.android,
      TargetPlatform.iOS => DevicePlatform.ios,
      TargetPlatform.macOS => DevicePlatform.macos,
      TargetPlatform.windows => DevicePlatform.windows,
      TargetPlatform.linux || TargetPlatform.fuchsia => DevicePlatform.other,
    };
