import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../state/controllers.dart';
import '../state/explorer_state.dart';
import '../state/key_alias.dart';
import '../widgets/form_widgets.dart';

/// Every `BiometricError` code: meaning, platforms, how to trigger it, and
/// one-tap triggers where that is possible without special hardware.
class ErrorsScreen extends StatelessWidget {
  /// Creates the screen.
  const ErrorsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    final c = state.errors;
    return ListenableBuilder(
      listenable: Listenable.merge([state, c]),
      builder: (context, _) {
        final platform = state.platform;
        final android = platform == DevicePlatform.android;
        return ScreenList(
          children: [
            const ScreenIntro(
              'Errors never throw: every method returns them in result.code '
              '(and a human-readable result.error). Switch on the code; the '
              'message text is not stable.',
            ),
            UnexpectedErrorBanner(controller: c),
            SectionCard(
              title: 'One-tap triggers',
              subtitle: 'Each one makes the plugin return a specific code',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  _TriggerTile(
                    controller: c,
                    trigger: ErrorTrigger.keyAlreadyExists,
                    title: 'keyAlreadyExists',
                    description: 'Creates a silent scratch key under '
                        "'${KeyAlias.errorsScratch.value}', calls createKeys "
                        'again with failIfExists: true, then deletes the '
                        'scratch key.',
                  ),
                  _TriggerTile(
                    controller: c,
                    trigger: ErrorTrigger.invalidInputEmptyPayload,
                    title: 'invalidInput (empty payload)',
                    description: 'createSignatureFromBytes with an empty '
                        'Uint8List on the selected alias '
                        '(${state.selectedAlias.label}). Rejected before any '
                        'prompt.',
                  ),
                  _TriggerTile(
                    controller: c,
                    trigger: ErrorTrigger.invalidInputChallenge,
                    title: 'invalidInput (129-byte challenge)',
                    description: 'createKeys with an attestation challenge '
                        'one byte over the limit. Checked before any key is '
                        'touched.',
                    disabledReason: android
                        ? null
                        : 'Android only — elsewhere any challenge returns '
                            'notSupported first.',
                  ),
                  _TriggerTile(
                    controller: c,
                    trigger: ErrorTrigger.notSupportedAttestation,
                    title: 'notSupported (attestation)',
                    description: 'createKeys with a 32-byte attestation '
                        'challenge on a platform without key attestation. '
                        'Existing keys are not touched.',
                    disabledReason: android
                        ? 'Android 7+ supports attestation (it reports '
                            'notSupported on Android 6 or keystores that '
                            'cannot attest). Try it on iOS, macOS or Windows.'
                        : null,
                  ),
                  _TriggerTile(
                    controller: c,
                    trigger: ErrorTrigger.keyNotFound,
                    title: 'keyNotFound',
                    description: "Deletes '${KeyAlias.missing.value}', then "
                        'signs with it.',
                  ),
                  _TriggerTile(
                    controller: c,
                    trigger: ErrorTrigger.userCanceled,
                    title: 'userCanceled',
                    description: 'Shows a prompt (simplePrompt): dismiss it '
                        'with Cancel, back or a swipe.',
                  ),
                ],
              ),
            ),
            _InvalidationWalkthrough(controller: c),
            SectionCard(
              title: 'lockedOut / lockedOutPermanent',
              subtitle: 'Walkthrough',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const NoteList([
                    '1. Tap the button and present an unenrolled finger or '
                        'face (or cover the sensor) until the prompt gives '
                        'up — usually 5 failures.',
                    '2. Android returns lockedOut and unlocks after about '
                        '30 seconds; after repeated lockouts it returns '
                        'lockedOutPermanent until you unlock with the PIN.',
                    '3. iOS/macOS return lockedOut; Face ID / Touch ID stay '
                        'locked until you enter the passcode.',
                    'Recovery: simplePrompt with allowDeviceCredentials: '
                        'true lets the user unlock with the device credential.',
                  ]),
                  const SizedBox(height: 8),
                  _TriggerTile(
                    controller: c,
                    trigger: ErrorTrigger.lockedOut,
                    title: 'Try to trigger lockout',
                    description: 'simplePrompt with biometrics only.',
                  ),
                ],
              ),
            ),
            SectionCard(
              title: 'All ${BiometricError.values.length} codes',
              subtitle: 'guidanceFor(code) from the shared example package',
              child: Column(
                children: [
                  for (final code in BiometricError.values)
                    _CodeTile(code: code, current: platform),
                ],
              ),
            ),
          ],
        );
      },
    );
  }
}

class _TriggerTile extends StatelessWidget {
  const _TriggerTile({
    required this.controller,
    required this.trigger,
    required this.title,
    required this.description,
    this.disabledReason,
  });

  final ErrorsController controller;
  final ErrorTrigger trigger;
  final String title;
  final String description;
  final String? disabledReason;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    final theme = Theme.of(context);
    final outcome = c.outcomes[trigger];
    return Padding(
      key: ValueKey('errors.${trigger.name}'),
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title,
                        style: monospaceStyle(context,
                            base: theme.textTheme.titleSmall)),
                    const SizedBox(height: 2),
                    Text(description, style: theme.textTheme.bodySmall),
                    if (disabledReason != null)
                      Text(
                        disabledReason!,
                        style: theme.textTheme.bodySmall
                            ?.copyWith(color: context.statusColors.warning),
                      ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              RunButton(
                key: ValueKey('errors.${trigger.name}.run'),
                label: 'Run',
                tonal: true,
                busy: c.isBusy(ErrorsController.triggerOp(trigger)),
                onPressed:
                    disabledReason == null ? () => c.trigger(trigger) : null,
              ),
            ],
          ),
          if (outcome != null) ...[
            const SizedBox(height: 6),
            CheckRow(
              key: ValueKey('errors.${trigger.name}.outcome'),
              kind:
                  outcome.asExpected ? StatusKind.success : StatusKind.warning,
              title: outcome.summary,
              detail: outcome.error,
            ),
          ],
        ],
      ),
    );
  }
}

class _InvalidationWalkthrough extends StatelessWidget {
  const _InvalidationWalkthrough({required this.controller});

  final ErrorsController controller;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    final platform = c.state.platform;
    final supported =
        PlatformCapabilities.of(platform).supportsEnrollmentInvalidation;
    final alias = KeyAlias.explorerB.value;
    final enrollHint = switch (platform) {
      DevicePlatform.ios => 'Settings → Face ID & Passcode → Set Up an '
          'Alternate Appearance (or add a Touch ID fingerprint).',
      DevicePlatform.macos => 'System Settings → Touch ID & Password → Add '
          'Fingerprint.',
      _ => 'Settings → Security → Fingerprint (or Face unlock) → add one.',
    };
    return SectionCard(
      title: 'keyInvalidated',
      subtitle: 'Walkthrough — needs a real device',
      child: supported
          ? Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _TriggerTile(
                  controller: c,
                  trigger: ErrorTrigger.invalidationCreate,
                  title: '1. Create the key',
                  description: "createKeys on '$alias' with "
                      'setInvalidatedByBiometricEnrollment: true, '
                      'requireAuthentication: true, useDeviceCredentials: '
                      'false. Replaces any key under that alias.',
                ),
                _Step(
                  title: '2. Enroll a new fingerprint or face',
                  text: '$enrollHint Then come back to this screen.',
                ),
                _TriggerTile(
                  controller: c,
                  trigger: ErrorTrigger.invalidationSign,
                  title: '3. Sign with it',
                  description: 'createSignatureFromBytes returns '
                      'keyInvalidated without prompting. The key is left for '
                      'the app to delete.',
                ),
                _TriggerTile(
                  controller: c,
                  trigger: ErrorTrigger.invalidationCheck,
                  title: '4. getKeyInfo(checkValidity: true)',
                  description: 'Reports exists: true, isValid: false — use '
                      'this on launch to detect it before the user tries.',
                ),
                const _Step(
                  title: 'Recover',
                  text: 'Delete the key (Inventory), create a new one and '
                      'register its public key with the server again. A key '
                      'created with useDeviceCredentials: true is not '
                      'invalidated on iOS/macOS.',
                ),
              ],
            )
          : const CapabilityBanner(
              title: 'Not applicable on this platform',
              message: 'Windows Hello manages key lifetime itself; the '
                  'plugin never reports keyInvalidated there.',
            ),
    );
  }
}

class _Step extends StatelessWidget {
  const _Step({required this.title, required this.text});

  final String title;
  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title,
              style: monospaceStyle(context, base: theme.textTheme.titleSmall)),
          const SizedBox(height: 2),
          Text(text, style: theme.textTheme.bodySmall),
        ],
      ),
    );
  }
}

class _CodeTile extends StatelessWidget {
  const _CodeTile({required this.code, required this.current});

  final BiometricError code;
  final DevicePlatform current;

  @override
  Widget build(BuildContext context) {
    final g = guidanceFor(code);
    final theme = Theme.of(context);
    final action = recoveryActionLabel(g.action);
    final emitted = [
      for (final p in allPlatforms)
        if (g.emittedOn.contains(p)) p,
    ];
    return ExpansionTile(
      key: ValueKey('errors.code.${code.name}'),
      tilePadding: EdgeInsets.zero,
      title: Text(code.name,
          style: monospaceStyle(context, base: theme.textTheme.titleSmall)),
      subtitle: Text(g.title),
      trailing: g.emittedOn.contains(current)
          ? null
          : Tooltip(
              message: 'Not emitted on ${current.label}',
              child: const Icon(Icons.block, size: 18),
            ),
      expandedCrossAxisAlignment: CrossAxisAlignment.stretch,
      childrenPadding: const EdgeInsets.only(bottom: 12),
      children: [
        Text(g.message),
        const SizedBox(height: 8),
        Wrap(
          spacing: 6,
          runSpacing: 6,
          children: [
            for (final p in emitted)
              StatusChip(
                label: p.label,
                kind: p == current ? StatusKind.info : StatusKind.neutral,
                showIcon: false,
              ),
            StatusChip(
              label: g.isTransient ? 'transient' : 'not transient',
              kind: g.isTransient ? StatusKind.warning : StatusKind.neutral,
              showIcon: false,
            ),
          ],
        ),
        const SizedBox(height: 8),
        KeyValueRow(
          label: 'Recovery',
          value: '${g.action.name}${action == null ? '' : ' — "$action"'}',
          copyable: false,
        ),
        KeyValueRow(
          label: 'How to trigger',
          value: _howToTrigger(code),
          copyable: false,
        ),
      ],
    );
  }

  static String _howToTrigger(BiometricError code) => switch (code) {
        BiometricError.success => 'Any call that completes.',
        BiometricError.userCanceled =>
          'Dismiss any prompt — one-tap trigger above.',
        BiometricError.notAvailable => 'Use a device without a usable '
            'sensor, or disable it. Also: decrypt() on Windows, and an '
            'attestation request the keystore cannot serve yet (Android 13+, '
            'retry with a fresh challenge).',
        BiometricError.notEnrolled => 'Remove every fingerprint/face, then '
            'call simplePrompt or createKeys with enforceBiometric: true. On '
            'Android, biometricStrength: strong with only a Class 2 '
            'biometric enrolled also reports it.',
        BiometricError.lockedOut => 'Fail biometric authentication about 5 '
            'times — walkthrough above.',
        BiometricError.lockedOutPermanent => 'Android: keep failing after '
            'several temporary lockouts, until only the PIN, pattern or '
            'password unlocks biometrics.',
        BiometricError.keyNotFound =>
          'Use an alias without a key — one-tap trigger above.',
        BiometricError.keyInvalidated => 'Enroll a new fingerprint or face '
            'after creating a key — walkthrough above.',
        BiometricError.unknown => 'Rare by design. Example on Android: '
            'decrypt() with an EC key created without enableDecryption '
            '("Decryption not enabled for EC signing-only mode").',
        BiometricError.invalidInput => 'An empty payload or a 129-byte '
            'attestation challenge — one-tap triggers above. Also malformed '
            'base64/hex ciphertext (reported after the prompt on iOS/macOS).',
        BiometricError.securityUpdateRequired => 'Android only: the OS '
            'reports a known sensor vulnerability. Not triggerable on '
            'purpose.',
        BiometricError.notSupported => 'Request key attestation outside '
            'Android (one-tap trigger above), or on Android 6.',
        BiometricError.systemCanceled => 'Start a prompt, then send the app '
            'to the background while it is showing.',
        BiometricError.promptError => 'The prompt could not be shown, e.g. '
            'no foreground activity on Android. Not normally reachable from '
            'this app.',
        BiometricError.keyAlreadyExists =>
          'createKeys with failIfExists: true on an alias that has a key — '
              'one-tap trigger above.',
        BiometricError.passcodeNotSet => 'Remove the screen lock (this also '
            'removes biometrics), then create a key. On Android it appears '
            'with device credentials allowed; otherwise Android reports '
            'notAvailable or notEnrolled. The iOS Simulator often has no '
            'passcode.',
        BiometricError.authenticationFailed => 'Present an unrecognised '
            'finger or face until the platform stops retrying the attempt. '
            'The key stays valid.',
        BiometricError.notInteractive => 'iOS/macOS: call a prompting API '
            'while the app is in the background.',
      };
}
