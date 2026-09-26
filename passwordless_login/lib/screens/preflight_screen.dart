import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app_scope.dart';
import '../client/preflight.dart';
import '../widgets/app_scaffold.dart';

/// What this device can do: screen lock, biometrics and the platform's
/// capabilities, with guidance for anything missing.
class PreflightScreen extends StatefulWidget {
  /// Creates the screen.
  const PreflightScreen({super.key});

  @override
  State<PreflightScreen> createState() => _PreflightScreenState();
}

class _PreflightScreenState extends State<PreflightScreen> {
  PreflightResult? _result;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _check());
  }

  Future<void> _check() async {
    final client = AppScope.of(context).client;
    setState(() => _result = null);
    final result = await client.preflight();
    if (mounted) setState(() => _result = result);
  }

  @override
  Widget build(BuildContext context) {
    final r = _result;
    final services = AppScope.of(context);
    final caps = services.capabilities;
    final platform = services.platform;
    return AppScaffold(
      title: 'Device check',
      actions: [
        IconButton(
          tooltip: 'Check again',
          onPressed: r == null ? null : _check,
          icon: const Icon(Icons.refresh),
        ),
      ],
      body: PageList(children: [
        if (r == null)
          const Center(child: CircularProgressIndicator())
        else if (r.ready)
          const CapabilityBanner(
            kind: StatusKind.success,
            title: 'Ready',
            message: 'A screen lock is set and biometrics are enrolled, so '
                'a biometric-bound key can be created.',
          )
        else
          for (final issue in r.issues) ErrorBanner(guidance: issue),
        if (r != null)
          SectionCard(
            title: 'biometricAuthAvailable()',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                KeyValueRow(
                  label: 'canAuthenticate',
                  value: '${r.availability.canAuthenticate}',
                  copyable: false,
                ),
                KeyValueRow(
                  label: 'hasEnrolledBiometrics',
                  value: '${r.availability.hasEnrolledBiometrics}',
                  copyable: false,
                ),
                KeyValueRow(
                  label: 'availableBiometrics',
                  value: [
                    for (final b
                        in r.availability.availableBiometrics ?? const [])
                      if (b != null) b.name,
                  ].join(', '),
                  copyable: false,
                ),
                if (r.availability.reason != null)
                  KeyValueRow(
                    label: 'reason',
                    value: r.availability.reason!,
                    copyable: false,
                  ),
              ],
            ),
          ),
        if (r != null)
          SectionCard(
            title: 'isDeviceLockSet()',
            subtitle: switch (platform) {
              DevicePlatform.windows =>
                'On Windows: whether Windows Hello is set up',
              DevicePlatform.ios ||
              DevicePlatform.macos =>
                'On Apple: true also when it cannot tell',
              _ => 'Android: KeyguardManager.isDeviceSecure()',
            },
            child: KeyValueRow(
              label: 'Result',
              value: '${r.deviceLockSet}',
              copyable: false,
            ),
          ),
        SectionCard(
          title: '${platform.label} capabilities',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              KeyValueRow(
                label: 'Key attestation',
                value: caps.supportsAttestation ? 'yes' : 'no',
                copyable: false,
              ),
              KeyValueRow(
                label: 'EC P-256 keys',
                value: caps.supportsEcKeys ? 'yes' : 'no (RSA only)',
                copyable: false,
              ),
              KeyValueRow(
                label: 'Enrollment invalidation',
                value: caps.supportsEnrollmentInvalidation ? 'yes' : 'no',
                copyable: false,
              ),
              KeyValueRow(
                label: 'authenticationType',
                value: caps.authTypeReliability.name,
                copyable: false,
              ),
              const SizedBox(height: 8),
              for (final note in caps.notes)
                Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Explainer('• $note'),
                ),
            ],
          ),
        ),
      ]),
    );
  }
}
