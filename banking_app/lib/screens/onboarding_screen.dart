import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/bank_client.dart';
import '../client/key_setup.dart';
import '../server/models.dart';
import '../widgets/bank_widgets.dart';

/// Binds this device: preflight, one-time code, two keys, registration.
class OnboardingScreen extends StatefulWidget {
  /// Creates the screen.
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final _otp = TextEditingController();
  Preflight? _preflight;
  DeviceEnrollment? _attempt;
  bool _allowDeviceCredential = false;
  String? _step;
  Object? _error;

  bool get _busy => _step != null;

  @override
  void initState() {
    super.initState();
    _otp.addListener(() => setState(() {}));
    WidgetsBinding.instance.addPostFrameCallback((_) => _checkDevice());
  }

  @override
  void dispose() {
    _otp.dispose();
    super.dispose();
  }

  Future<void> _run(String step, Future<void> Function() action) async {
    setState(() {
      _step = step;
      _error = null;
    });
    try {
      await action();
    } catch (e) {
      if (mounted) setState(() => _error = e);
    } finally {
      if (mounted) setState(() => _step = null);
    }
  }

  Future<void> _checkDevice() =>
      _run('Checking biometrics and screen lock…', () async {
        final preflight = await AppScope.of(context).keys.preflight();
        if (mounted) setState(() => _preflight = preflight);
      });

  Future<void> _sendCode() =>
      _run('Asking the bank for a one-time code…', () async {
        final services = AppScope.of(context);
        final attempt = _attempt ??= DeviceEnrollment(
          keys: services.keys,
          client: services.client,
          previousDeviceId: services.session.previousDeviceId,
        );
        _otp.clear();
        await attempt.begin();
        if (mounted) setState(() {});
      });

  Future<void> _bind() async {
    final attempt = _attempt;
    if (attempt == null) return;
    final services = AppScope.of(context);
    await _run('Creating keys…', () async {
      final result = await attempt.complete(
        otp: _otp.text,
        allowDeviceCredential: _allowDeviceCredential,
        onStep: (step) {
          if (mounted) setState(() => _step = step);
        },
      );
      await services.session.completeEnrollment(result,
          attempt: attempt, allowDeviceCredential: _allowDeviceCredential);
    });
  }

  Future<void> _replaceExisting(String alias) async {
    await _attempt?.replaceExisting(alias);
    await _bind();
  }

  Future<void> _continueWithoutAttestation() async {
    _attempt?.skipAttestation = true;
    await _bind();
  }

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final theme = Theme.of(context);
    final start = _attempt?.start;
    final platform = services.platform;
    final lostReason = services.session.bindingLostReason;
    return BankScaffold(
      title: 'Step-up Banking',
      body: ListView(
        padding: pagePadding(context),
        children: [
          Text('Bind this device', style: theme.textTheme.headlineSmall),
          const SizedBox(height: 8),
          const Text(
              'Two keys protect your account. device_binding signs every '
              'request to the bank silently: it proves the request comes '
              'from this device, not that you are holding it. txn_approval '
              'asks for your biometric and signs the exact bytes of larger '
              'transfers. The bank verifies both (this is a demo mock '
              'server).'),
          gap,
          const _KeysTable(),
          if (lostReason != null) ...[
            gap,
            CapabilityBanner(
              kind: StatusKind.warning,
              title: 'Bind this device again',
              message: lostReason,
            ),
          ],
          if (services.capabilities.silentKeysPrompt) ...[
            gap,
            const CapabilityBanner(
              kind: StatusKind.warning,
              title: 'Windows Hello prompts for every request',
              message: 'Windows Hello prompts even for the device-binding '
                  'key, so background request signing prompts every time. '
                  'Auto-refresh is off; pull to refresh instead.',
            ),
          ],
          if (!services.capabilities.supportsAttestation) ...[
            gap,
            CapabilityBanner(
              title: 'Unattested — capped at tier B',
              message: '${platform.label} cannot attest individual keys, so '
                  'the bank cannot verify that the approval key is '
                  'biometric-only. Transfers above the tier B limit are '
                  'declined while the policy "Require attested '
                  'biometric-only key for tier C" is on (server console → '
                  'Policy).',
            ),
          ],
          gap,
          _preflightCard(context),
          gap,
          SectionCard(
            title: '2 · Verify it\'s you',
            subtitle: 'Demo customer: Alex Morgan (signed in with a '
                'simulated password)',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text('Binding a device needs a second factor. The bank '
                    'sends a one-time code and issues fresh, single-use '
                    'attestation challenges for both keys.'),
                const SizedBox(height: 12),
                Align(
                  alignment: Alignment.centerLeft,
                  child: OutlinedButton.icon(
                    key: const ValueKey('send-code'),
                    onPressed: _busy || _preflight?.canProceed != true
                        ? null
                        : _sendCode,
                    icon: const Icon(Icons.sms_outlined),
                    label:
                        Text(start == null ? 'Send code' : 'Send a new code'),
                  ),
                ),
                if (start != null) ...[
                  const SizedBox(height: 12),
                  SimulatedSmsCard(
                    outbox: services.server.outbox,
                    subject: start.enrollmentId,
                    onUseCode: (code) => _otp.text = code,
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    key: const ValueKey('otp-field'),
                    controller: _otp,
                    keyboardType: TextInputType.number,
                    maxLength: 6,
                    decoration: InputDecoration(
                      labelText: 'One-time code',
                      helperText: 'Sent to ${start.otpSentTo}',
                    ),
                  ),
                ],
              ],
            ),
          ),
          gap,
          SectionCard(
            title: '3 · Create keys and bind',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _allowDeviceCredential,
                  onChanged: _busy
                      ? null
                      : (v) => setState(() => _allowDeviceCredential = v),
                  title: const Text('Allow device PIN / passcode for '
                      'approvals'),
                  subtitle: const Text('useDeviceCredentials. Off by '
                      'default: a PIN fallback means the key can no longer '
                      'qualify for tier C (Android attests it as userAuthType '
                      '3), and on iOS/macOS such keys survive biometric '
                      'enrollment changes.'),
                ),
                const SizedBox(height: 8),
                FilledButton.icon(
                  key: const ValueKey('bind-device'),
                  onPressed: _busy ||
                          start == null ||
                          _otp.text.trim().length != 6 ||
                          _preflight?.canProceed != true
                      ? null
                      : _bind,
                  icon: const Icon(Icons.fingerprint),
                  label: const Text('Create keys & bind device'),
                ),
                if (_busy) ...[
                  const SizedBox(height: 12),
                  BusyStep(_step!),
                ],
              ],
            ),
          ),
          if (_error != null) ...[gap, _errorView(context, _error!)],
        ],
      ),
    );
  }

  Widget _preflightCard(BuildContext context) {
    final p = _preflight;
    return SectionCard(
      title: '1 · Check this device',
      subtitle: 'biometricAuthAvailable() and isDeviceLockSet()',
      trailing: TextButton(
        onPressed: _busy ? null : _checkDevice,
        child: const Text('Check again'),
      ),
      child: p == null
          ? const Text('Checking…')
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                CheckRow(
                  kind:
                      p.deviceLockSet ? StatusKind.success : StatusKind.danger,
                  title: p.platform == DevicePlatform.windows
                      ? 'Windows Hello is set up'
                      : 'Screen lock is set',
                  detail: p.deviceLockSet
                      ? null
                      : 'Required before any key that needs user '
                          'authentication can be created.',
                ),
                CheckRow(
                  kind: p.biometricsReady
                      ? StatusKind.success
                      : StatusKind.danger,
                  title: 'Biometrics available',
                  detail: 'Enrolled: ${p.biometricTypes}'
                      '${p.availability.reason == null ? '' : ' — ${p.availability.reason}'}',
                ),
                for (final problem in p.problems)
                  Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Text(problem,
                        style: TextStyle(color: context.statusColors.danger)),
                  ),
              ],
            ),
    );
  }

  Widget _errorView(BuildContext context, Object error) {
    if (error is KeySetupException) {
      if (error.code == BiometricError.keyAlreadyExists) {
        return CapabilityBanner(
          kind: StatusKind.warning,
          title: 'A "${error.alias}" key already exists (keyAlreadyExists)',
          message: 'It was left by an earlier install (the iOS keychain '
              'survives uninstalling, for example). The bank has no record '
              'of it for this binding, and failIfExists: true refused to '
              'overwrite it silently. Delete it and create a new key?',
          action: FilledButton.tonal(
            onPressed: _busy ? null : () => _replaceExisting(error.alias),
            child: const Text('Replace key'),
          ),
        );
      }
      if (error.attestationNotReady) {
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ErrorBanner(
              guidance: guidanceFor(error.code),
              rawMessage: error.message,
              actionLabel: 'Retry with a new challenge',
              onAction: _busy ? null : _sendCode,
            ),
            const SizedBox(height: 8),
            OutlinedButton(
              onPressed: _busy ? null : _continueWithoutAttestation,
              child: const Text('Continue without attestation (tier B max)'),
            ),
          ],
        );
      }
      final guidance = guidanceFor(error.code);
      final recheck = error.code == BiometricError.passcodeNotSet ||
          error.code == BiometricError.notEnrolled;
      return ErrorBanner(
        guidance: guidance,
        rawMessage: '${error.alias}: ${error.message}',
        actionLabel: recheck ? 'Check again' : 'Try again',
        onAction: _busy ? null : (recheck ? _checkDevice : _bind),
      );
    }
    if (error is BankError) {
      if (error.kind == BankErrorKind.signing) {
        // The enrollment request is signed by the new device_binding key
        // (Windows Hello prompts for it).
        return ErrorBanner(
          guidance: guidanceFor(error.code),
          rawMessage: '${KeyAliases.deviceBinding}: ${error.message}',
          actionLabel: 'Try again',
          onAction: _busy ? null : _bind,
        );
      }
      return SectionCard(
        title: 'The bank rejected the enrollment',
        subtitle: error.message,
        child: ChecksView([...error.requestChecks, ...error.checks],
            emptyText: error.kind == BankErrorKind.network
                ? 'The request did not reach the bank. Try again.'
                : 'No details.'),
      );
    }
    return ErrorBanner(
        guidance: guidanceFor(BiometricError.unknown), rawMessage: '$error');
  }
}

class _KeysTable extends StatelessWidget {
  const _KeysTable();

  @override
  Widget build(BuildContext context) {
    return const SectionCard(
      title: 'The two keys',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          KeyValueRow(
            label: KeyAliases.deviceBinding,
            value: 'ECDSA P-256, requireAuthentication: false, failIfExists, '
                'attested on Android. Signs every request without a prompt. '
                'Proves possession of this device only.',
            copyable: false,
          ),
          KeyValueRow(
            label: KeyAliases.approval,
            value: 'ECDSA P-256, enforceBiometric, '
                'setInvalidatedByBiometricEnrollment: true, failIfExists, '
                'attested on Android. Signs transfer payloads after a '
                'biometric prompt.',
            copyable: false,
          ),
        ],
      ),
    );
  }
}
