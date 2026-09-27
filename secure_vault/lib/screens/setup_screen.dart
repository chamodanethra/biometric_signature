import 'dart:async';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/vault_controller.dart';
import '../client/vault_key_manager.dart';
import '../models/vault_key_record.dart';
import '../widgets/common.dart';
import 'server_console_screen.dart';
import 'share_screen.dart';

/// Preflight, key type choice and provisioning.
class SetupScreen extends StatefulWidget {
  /// Creates the screen.
  const SetupScreen({super.key});

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> {
  VaultKeyChoice _choice = VaultKeyChoice.ec;
  bool _useDeviceCredentials = false;
  Future<Preflight>? _preflight;
  ProvisionOutcome? _outcome;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _preflight ??= AppScope.read(context).preflight();
  }

  void _recheck() =>
      setState(() => _preflight = AppScope.read(context).preflight());

  Future<void> _run(
      Future<ProvisionOutcome> Function(VaultController c) action) async {
    final controller = AppScope.read(context);
    final messenger = ScaffoldMessenger.of(context);
    setState(() => _outcome = null);
    final outcome = await action(controller);
    if (outcome is Provisioned) {
      showSnack(
        messenger,
        outcome.syncError == null
            ? 'Vault ready: ${outcome.itemsReceived} secrets arrived sealed '
                'with ${outcome.scheme.label}.'
            : 'Vault key registered, but the first sync failed: '
                '${outcome.syncError}',
      );
    }
    if (mounted) setState(() => _outcome = outcome);
  }

  Future<void> _create() => _run((c) => c.provision(
        choice: _choice,
        useDeviceCredentials: _useDeviceCredentials,
      ));

  Future<void> _registerExisting() => _run((c) => c.registerExistingKey(
        useDeviceCredentials: _useDeviceCredentials,
      ));

  Future<void> _replaceExisting() async {
    final ok = await confirmAction(
      context,
      title: 'Replace the existing key?',
      message: 'deleteKeys(keyAlias: "vault") removes it for good. Anything '
          'sealed to it can never be opened again.',
      confirmLabel: 'Replace',
    );
    if (!ok || !mounted) return;
    await _run((c) => c.replaceExistingKey(
          choice: _choice,
          useDeviceCredentials: _useDeviceCredentials,
        ));
  }

  void _openSealOnly() {
    unawaited(Navigator.of(context).push(MaterialPageRoute<void>(
      builder: (context) => const ShareScreen(senderOnly: true),
    )));
  }

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final supported = controller.capabilities.supportsDecrypt;
        final busy = controller.busy;
        return DevConsoleScaffold(
          title: const Text('Secure Vault'),
          consoleTabs: serverConsoleTabs(controller),
          body: PageBody(children: [
            const _Intro(),
            if (!supported) _unsupportedBanner(controller.platform),
            _PreflightCard(future: _preflight, onRecheck: _recheck),
            if (supported) _keyChoiceCard(controller.platform),
            if (supported &&
                controller.existingKeyOnDevice &&
                _outcome == null &&
                busy == null)
              CapabilityBanner(
                title: 'A vault key already exists on this device',
                message: 'Keys can outlive app data (the iOS keychain keeps '
                    'them across reinstalls). Setup uses failIfExists: true, '
                    'so it never overwrites a key silently: register the '
                    'existing key or replace it.',
                action: _existingKeyActions(),
              ),
            if (_outcome != null) _outcomeView(_outcome!),
            if (supported)
              Align(
                alignment: Alignment.centerLeft,
                child: FilledButton.icon(
                  onPressed: busy == null ? _create : null,
                  icon: const Icon(Icons.enhanced_encryption_outlined),
                  label: const Text('Create vault key'),
                ),
              ),
            if (busy != null) BusyRow(busy),
            const _HowItWorks(),
          ]),
        );
      },
    );
  }

  Widget _unsupportedBanner(DevicePlatform platform) => CapabilityBanner(
        kind: StatusKind.warning,
        title: platform == DevicePlatform.windows
            ? 'Windows Hello cannot decrypt'
            : 'This platform is not supported',
        message: platform == DevicePlatform.windows
            ? 'Windows Hello keys are RSA-only and have no decrypt operation: '
                'decrypt() returns notAvailable, so there is no vault to '
                'reveal here. You can still seal a secret for someone '
                "else's vault: sealing needs only their public key."
            : 'biometric_signature supports Android, iOS, macOS and Windows.',
        action: platform == DevicePlatform.windows
            ? FilledButton.tonalIcon(
                onPressed: _openSealOnly,
                icon: const Icon(Icons.outbox_outlined),
                label: const Text('Seal a secret for another vault'),
              )
            : null,
      );

  Widget _keyChoiceCard(DevicePlatform platform) => SectionCard(
        title: 'Vault key',
        subtitle: 'Alias "vault" · created with failIfExists: true',
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SegmentedButton<VaultKeyChoice>(
              segments: [
                for (final c in VaultKeyChoice.values)
                  ButtonSegment(value: c, label: Text(c.label)),
              ],
              selected: {_choice},
              onSelectionChanged: (s) => setState(() => _choice = s.first),
            ),
            const SizedBox(height: 8),
            Text(
              'On ${platform.label}: '
              '${VaultKeyManager.expectedSchemeSummary(platform, _choice)}',
            ),
            const SizedBox(height: 4),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Accept the device PIN / passcode too'),
              subtitle: Text(platform.isApple
                  ? 'useDeviceCredentials. On iOS and macOS such a key is '
                      'not invalidated by new biometrics (the passcode can '
                      'always unlock it), so leave this off to see '
                      'crypto-shredding.'
                  : 'useDeviceCredentials, and allowDeviceCredentials on '
                      'each reveal. Off: biometrics only.'),
              value: _useDeviceCredentials,
              onChanged: (v) => setState(() => _useDeviceCredentials = v),
            ),
            const Caption('setInvalidatedByBiometricEnrollment: true — '
                'enrolling a new fingerprint or face permanently disables '
                'the key, and with it everything sealed to it.'),
          ],
        ),
      );

  Widget _existingKeyActions() => Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          FilledButton.tonal(
            onPressed: _registerExisting,
            child: const Text('Register the existing key'),
          ),
          OutlinedButton(
            onPressed: _replaceExisting,
            child: const Text('Replace it'),
          ),
        ],
      );

  Widget _outcomeView(ProvisionOutcome outcome) {
    switch (outcome) {
      case Provisioned():
        return const SizedBox.shrink();
      case KeyCreationFailed(:final code, :final message):
        if (code == BiometricError.keyAlreadyExists) {
          return ErrorBanner(
            guidance: guidanceFor(code),
            rawMessage: message,
            onAction: _registerExisting,
            actionLabel: 'Register the existing key',
          );
        }
        final guidance = guidanceFor(code);
        final retry = guidance.action == RecoveryAction.retry ||
            guidance.action == RecoveryAction.retryLater;
        return ErrorBanner(
          guidance: guidance,
          rawMessage: message,
          onAction: retry ? _create : _recheck,
          actionLabel: retry ? 'Try again' : 'Check again',
        );
      case RegistrationFailed(:final message, :final rejected):
        return CapabilityBanner(
          kind: StatusKind.danger,
          title: rejected
              ? 'The server refused the key'
              : 'Registration did not reach the server',
          message: rejected
              ? message
              : '$message. The key was created on this device, but the '
                  'server never received it. Retrying reads the public key '
                  'back with getKeyInfo and sends it again; no new key, no '
                  'prompt.',
          action: rejected
              ? null
              : FilledButton.tonal(
                  onPressed: _registerExisting,
                  child: const Text('Retry registration'),
                ),
        );
    }
  }
}

class _Intro extends StatelessWidget {
  const _Intro();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Secrets only your biometrics can open',
            style: theme.textTheme.headlineSmall),
        const SizedBox(height: 8),
        const Text(
          'A provisioning server seals secrets to a key that lives in secure '
          'hardware on this device. The device stores only ciphertext. A '
          'secret becomes readable only inside decrypt(), after a successful '
          'biometric check, and only for as long as you look at it.',
        ),
      ],
    );
  }
}

class _PreflightCard extends StatelessWidget {
  const _PreflightCard({required this.future, required this.onRecheck});

  final Future<Preflight>? future;
  final VoidCallback onRecheck;

  @override
  Widget build(BuildContext context) {
    return SectionCard(
      title: 'Preflight',
      subtitle: 'biometricAuthAvailable() and isDeviceLockSet()',
      trailing: IconButton(
        icon: const Icon(Icons.refresh),
        tooltip: 'Check again',
        onPressed: onRecheck,
      ),
      child: FutureBuilder<Preflight>(
        future: future,
        builder: (context, snapshot) {
          final p = snapshot.data;
          if (p == null) {
            return snapshot.hasError
                ? Text('Could not check: ${snapshot.error}')
                : const BusyRow('Checking…');
          }
          final blocker = p.blocker;
          final windows = p.platform == DevicePlatform.windows;
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              CheckRow(
                kind: p.availability.canAuthenticate == true
                    ? StatusKind.success
                    : StatusKind.warning,
                title: p.availability.canAuthenticate == true
                    ? 'Biometrics available'
                    : 'Biometrics not available',
                detail: 'Enrolled: ${p.biometricsLabel}'
                    '${p.availability.reason == null ? '' : ' · ${p.availability.reason}'}',
              ),
              CheckRow(
                kind: p.deviceLockSet ? StatusKind.success : StatusKind.danger,
                title: windows
                    ? (p.deviceLockSet
                        ? 'Windows Hello is set up'
                        : 'Windows Hello is not set up')
                    : (p.deviceLockSet
                        ? 'Screen lock is set'
                        : 'No screen lock'),
                detail: windows
                    ? 'On Windows, isDeviceLockSet() reports Windows Hello '
                        'availability.'
                    : 'Hardware-backed keys require a PIN, pattern, password '
                        'or passcode.',
              ),
              if (blocker != null) ...[
                const SizedBox(height: 8),
                ErrorBanner(guidance: guidanceFor(blocker)),
              ],
            ],
          );
        },
      ),
    );
  }
}

class _HowItWorks extends StatelessWidget {
  const _HowItWorks();

  @override
  Widget build(BuildContext context) {
    const steps = [
      'createKeys(keyAlias: "vault", enableDecryption: true, '
          'setInvalidatedByBiometricEnrollment: true, failIfExists: true).',
      'The public key goes to the provisioning server, which resolves the '
          'encryption scheme from the platform and the key (EncryptionTarget).',
      'The server seals its secrets; the device stores the ciphertext.',
      'Reveal = decrypt() behind a biometric prompt. The private key never '
          'leaves secure hardware.',
    ];
    return SectionCard(
      title: 'What happens',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          for (var i = 0; i < steps.length; i++)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  CircleAvatar(radius: 11, child: Text('${i + 1}')),
                  const SizedBox(width: 10),
                  Expanded(child: Text(steps[i])),
                ],
              ),
            ),
        ],
      ),
    );
  }
}
