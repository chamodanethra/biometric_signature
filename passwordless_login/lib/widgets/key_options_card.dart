import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../client/auth_client.dart';

/// The user-chosen `createKeys` flags, with what each one means.
class KeyOptionsCard extends StatelessWidget {
  /// Creates the card.
  const KeyOptionsCard({
    super.key,
    required this.options,
    required this.platform,
    required this.onChanged,
    this.enabled = true,
  });

  /// Current options.
  final KeyOptions options;

  /// Running platform (Windows ignores both flags).
  final DevicePlatform platform;

  /// Called with new options.
  final ValueChanged<KeyOptions> onChanged;

  /// Whether the switches are enabled.
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    final windows = platform == DevicePlatform.windows;
    return SectionCard(
      title: 'Key options',
      subtitle: windows
          ? 'Windows Hello ignores both flags'
          : 'CreateKeysConfig flags for this account’s key',
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          SwitchListTile(
            key: const Key('opt-device-credentials'),
            contentPadding: EdgeInsets.zero,
            value: options.allowDeviceCredentials,
            onChanged: !enabled || windows
                ? null
                : (v) => onChanged(KeyOptions(
                      allowDeviceCredentials: v,
                      invalidateOnEnrollment: options.invalidateOnEnrollment,
                    )),
            title: const Text('Allow device PIN / passcode'),
            subtitle: const Text(
              'useDeviceCredentials. Off: biometric only — on Android the '
              'attestation then proves userAuthType = biometric. On: the '
              'device credential also unlocks the key, and sign-in passes '
              'allowDeviceCredentials.',
            ),
          ),
          SwitchListTile(
            key: const Key('opt-invalidate'),
            contentPadding: EdgeInsets.zero,
            value: options.invalidateOnEnrollment,
            onChanged: !enabled || windows
                ? null
                : (v) => onChanged(KeyOptions(
                      allowDeviceCredentials: options.allowDeviceCredentials,
                      invalidateOnEnrollment: v,
                    )),
            title: const Text('Invalidate when biometrics change'),
            subtitle: Text(
              'setInvalidatedByBiometricEnrollment. Enrolling a new '
              'fingerprint or face permanently disables the key '
              '(keyInvalidated), so someone who learns the PIN cannot add '
              'their own finger and sign in. You then re-bind with the '
              'recovery code.'
              '${platform.isApple && options.allowDeviceCredentials && options.invalidateOnEnrollment ? '\nOn ${platform.label}, a key that also accepts the passcode is never invalidated.' : ''}',
            ),
          ),
        ],
      ),
    );
  }
}
