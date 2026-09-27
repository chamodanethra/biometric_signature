import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../state/controllers.dart';
import '../state/explorer_state.dart';
import '../state/result_fields.dart';
import '../version.dart';
import '../widgets/form_widgets.dart';
import '../widgets/result_card.dart';

/// `biometricAuthAvailable`, `isDeviceLockSet` and the platform capability
/// matrix.
class DeviceScreen extends StatelessWidget {
  /// Creates the screen.
  const DeviceScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    final c = state.device;
    return ListenableBuilder(
      listenable: c,
      builder: (context, _) {
        final platform = state.platform;
        return ScreenList(
          children: [
            ScreenIntro(
              'biometric_signature $pluginVersion on ${platform.label}. Start '
              'here: can this device authenticate, and does it have a screen '
              'lock? Both calls are free (no prompt).',
            ),
            if (platform == DevicePlatform.other)
              const CapabilityBanner(
                title: 'Unsupported platform',
                message: 'The plugin supports Android, iOS, macOS and '
                    'Windows. Calls on this platform throw '
                    'MissingPluginException; the Explorer shows them as '
                    'unexpected exceptions.',
                kind: StatusKind.danger,
              ),
            UnexpectedErrorBanner(controller: c),
            SectionCard(
              title: 'biometricAuthAvailable()',
              subtitle: 'Returns BiometricAvailability',
              trailing: RunButton(
                key: const ValueKey('device.availability'),
                label: 'Check',
                icon: Icons.refresh,
                tonal: true,
                busy: c.isBusy(DeviceController.availabilityOp),
                onPressed: c.checkAvailability,
              ),
              child: c.availability == null
                  ? const Text('Not checked yet.')
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        for (final f in resultFieldsOf(c.availability))
                          ResultFieldRow(field: f),
                        const SizedBox(height: 8),
                        const NoteList([
                          'canAuthenticate: whether a biometric prompt can '
                              'succeed right now (enrolled, not locked out).',
                          'availableBiometrics lists sensor types; '
                              '"multiple" means more than one kind.',
                          'reason explains a false canAuthenticate.',
                        ]),
                      ],
                    ),
            ),
            SectionCard(
              title: 'isDeviceLockSet()',
              subtitle: 'Returns bool',
              trailing: RunButton(
                key: const ValueKey('device.lock'),
                label: 'Check',
                icon: Icons.refresh,
                tonal: true,
                busy: c.isBusy(DeviceController.lockOp),
                onPressed: c.checkDeviceLock,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  if (c.deviceLockSet == null)
                    const Text('Not checked yet.')
                  else
                    KeyValueRow(
                      label: 'result',
                      value: '${c.deviceLockSet}',
                      copyable: false,
                    ),
                  const SizedBox(height: 8),
                  Text(_lockSemantics(platform)),
                ],
              ),
            ),
            SectionCard(
              title: 'Platform capabilities',
              subtitle: 'From the plugin\'s native code, not just its README',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  _CapabilityMatrix(current: platform),
                  const SizedBox(height: 12),
                  Text('On ${platform.label}',
                      style: Theme.of(context).textTheme.titleSmall),
                  const SizedBox(height: 4),
                  NoteList(PlatformCapabilities.of(platform).notes),
                ],
              ),
            ),
          ],
        );
      },
    );
  }

  static String _lockSemantics(DevicePlatform platform) => switch (platform) {
        DevicePlatform.android => 'Android: authoritative '
            '(KeyguardManager.isDeviceSecure).',
        DevicePlatform.ios ||
        DevicePlatform.macos =>
          '${platform.label}: false only for "passcode not set"; other '
              'failures report true, so true means "set or indeterminate". '
              'The next operation reports passcodeNotSet if it is missing.',
        DevicePlatform.windows => 'Windows: reports Windows Hello '
            'availability (a Hello PIN), not the generic screen lock. '
            'Password-only accounts get false.',
        DevicePlatform.other => 'Not supported on this platform.',
      };
}

/// All result fields of [result] (none for `null`).
List<ResultField> resultFieldsOf(Object? result) =>
    result == null ? const [] : resultFields(result);

class _CapabilityMatrix extends StatelessWidget {
  const _CapabilityMatrix({required this.current});

  final DevicePlatform current;

  static const _platforms = [
    DevicePlatform.android,
    DevicePlatform.ios,
    DevicePlatform.macos,
    DevicePlatform.windows,
  ];

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = context.statusColors;
    final caps = {for (final p in _platforms) p: PlatformCapabilities.of(p)};

    Widget header(String text, {bool highlight = false}) => Padding(
          padding: const EdgeInsets.all(8),
          child: Text(
            text,
            style: theme.textTheme.labelLarge?.copyWith(
              fontWeight: highlight ? FontWeight.w800 : FontWeight.w600,
              color: highlight ? theme.colorScheme.primary : null,
            ),
          ),
        );

    Widget yesNo(bool value) => Padding(
          padding: const EdgeInsets.all(8),
          child: Icon(
            value ? Icons.check_circle : Icons.remove_circle_outline,
            size: 20,
            color: value ? colors.success : theme.colorScheme.outline,
            semanticLabel: value ? 'yes' : 'no',
          ),
        );

    Widget text(String value) => Padding(
          padding: const EdgeInsets.all(8),
          child: Text(value, style: theme.textTheme.bodySmall),
        );

    TableRow row(String label, Widget Function(PlatformCapabilities) cell) =>
        TableRow(children: [
          text(label),
          for (final p in _platforms) cell(caps[p]!),
        ]);

    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Table(
        defaultColumnWidth: const IntrinsicColumnWidth(),
        defaultVerticalAlignment: TableCellVerticalAlignment.middle,
        border: TableBorder(
          horizontalInside: BorderSide(color: theme.colorScheme.outlineVariant),
        ),
        children: [
          TableRow(children: [
            header('Capability'),
            for (final p in _platforms)
              header(p == current ? '${p.label}\n(this device)' : p.label,
                  highlight: p == current),
          ]),
          row('EC P-256 keys', (c) => yesNo(c.supportsEcKeys)),
          row('decrypt()', (c) => yesNo(c.supportsDecrypt)),
          row('Key attestation', (c) => yesNo(c.supportsAttestation)),
          row('Silent keys never prompt', (c) => yesNo(c.supportsSilentKeys)),
          row('Invalidation on enrollment change',
              (c) => yesNo(c.supportsEnrollmentInvalidation)),
          row(
            'authenticationType',
            (c) => text(switch (c.authTypeReliability) {
              AuthTypeReliability.authoritative => 'reported',
              AuthTypeReliability.inferred => 'inferred',
              AuthTypeReliability.notReported => 'always unknown',
            }),
          ),
        ],
      ),
    );
  }
}
