import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../state/controllers.dart';
import '../state/explorer_state.dart';
import '../state/result_fields.dart';
import '../widgets/alias_picker.dart';
import '../widgets/form_widgets.dart';
import '../widgets/result_card.dart';

/// `createKeys` with every argument.
class KeysScreen extends StatelessWidget {
  /// Creates the screen.
  const KeysScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    final c = state.keys;
    return ListenableBuilder(
      listenable: Listenable.merge([state, c]),
      builder: (context, _) {
        final platform = state.platform;
        final caps = state.capabilities;
        final busy = c.isBusy(KeysController.createOp);
        return ScreenList(
          children: [
            const ScreenIntro(
              'createKeys generates a hardware-backed key pair under an '
              'alias and returns its public key — send that to your server. '
              'Every argument is below; tags show which platforms honour '
              'each one.',
            ),
            UnexpectedErrorBanner(controller: c),
            const SectionCard(title: 'Alias', child: AliasPicker()),
            SectionCard(
              title: 'Presets',
              subtitle: 'Fill the form with a common combination',
              child: Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  for (final p in KeyPreset.values)
                    ActionChip(
                      key: ValueKey('keys.preset.${p.name}'),
                      label: Text(p.label),
                      onPressed: busy ? null : () => c.applyPreset(p),
                    ),
                ],
              ),
            ),
            SectionCard(
              title: 'Key',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  if (!caps.supportsEcKeys)
                    const CapabilityBanner(
                      title: 'RSA only on Windows',
                      message: 'Windows Hello keys are RSA-2048; '
                          'signatureType is ignored, so EC is disabled here.',
                    ),
                  EnumChoice<SignatureType>(
                    key: const ValueKey('keys.signatureType'),
                    name: 'config.signatureType',
                    platforms: mobileAndMac,
                    values: SignatureType.values,
                    selected: c.signatureType,
                    labelOf: (v) => v == SignatureType.rsa ? 'RSA' : 'ECDSA',
                    isEnabled: (v) =>
                        v == SignatureType.rsa || caps.supportsEcKeys,
                    onChanged: busy
                        ? null
                        : (v) => c.update(() => c.signatureType = v),
                    description: _signatureTypeHelp(platform, c.signatureType),
                  ),
                  EnumChoice<KeyFormat>(
                    key: const ValueKey('keys.keyFormat'),
                    name: 'keyFormat',
                    platforms: allPlatforms,
                    values: KeyFormat.values,
                    selected: c.keyFormat,
                    onChanged:
                        busy ? null : (v) => c.update(() => c.keyFormat = v),
                    description: '${_keyFormatHelp(c.keyFormat)} '
                        'publicKeyBytes is always returned. '
                        '${_publicKeyBytesLayout(platform, c.signatureType)}',
                  ),
                ],
              ),
            ),
            SectionCard(
              title: 'Access control',
              subtitle: 'CreateKeysConfig booleans',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  OptionSwitch(
                    key: const ValueKey('keys.requireAuthentication'),
                    name: 'requireAuthentication',
                    platforms: mobileAndMac,
                    value: c.requireAuthentication,
                    description: 'false creates a silent device key: signing '
                        'and decryption never prompt. It proves possession '
                        'of the device, not user presence.',
                    onChanged: busy
                        ? null
                        : (v) => c.update(() => c.requireAuthentication = v),
                  ),
                  if (!c.requireAuthentication)
                    CapabilityBanner(
                      title: 'Silent key',
                      kind: StatusKind.warning,
                      message: 'enforceBiometric, useDeviceCredentials and '
                          'setInvalidatedByBiometricEnrollment are ignored for '
                          'a key without user authentication, and '
                          'authenticationType reports unknown.'
                          '${caps.silentKeysPrompt ? ' Windows Hello still '
                              'prompts for every use.' : ''}',
                    ),
                  OptionSwitch(
                    key: const ValueKey('keys.enforceBiometric'),
                    name: 'enforceBiometric',
                    platforms: mobileAndMac,
                    value: c.enforceBiometric,
                    description: 'Prompt once while creating the key, so '
                        'creation proves a biometric is enrolled and works.',
                    onChanged: busy
                        ? null
                        : (v) => c.update(() => c.enforceBiometric = v),
                  ),
                  OptionSwitch(
                    key: const ValueKey('keys.useDeviceCredentials'),
                    name: 'useDeviceCredentials',
                    platforms: mobileAndMac,
                    value: c.useDeviceCredentials,
                    description: 'Allow the device PIN, pattern or passcode '
                        'instead of a biometric when the key is used. On '
                        'iOS/macOS such a key survives enrollment changes.',
                    onChanged: busy
                        ? null
                        : (v) => c.update(() => c.useDeviceCredentials = v),
                  ),
                  OptionSwitch(
                    key: const ValueKey(
                        'keys.setInvalidatedByBiometricEnrollment'),
                    name: 'setInvalidatedByBiometricEnrollment',
                    platforms: mobileAndMac,
                    value: c.setInvalidatedByBiometricEnrollment,
                    description: 'Adding or removing a fingerprint or face '
                        'permanently invalidates the key (keyInvalidated). '
                        'Defaults to true.',
                    onChanged: busy
                        ? null
                        : (v) => c.update(
                            () => c.setInvalidatedByBiometricEnrollment = v),
                  ),
                  OptionSwitch(
                    key: const ValueKey('keys.enableDecryption'),
                    name: 'enableDecryption',
                    platforms: androidOnly,
                    value: c.enableDecryption,
                    description: 'Android: allow decrypt(). With ECDSA this '
                        'is hybrid mode (a separate software EC key for '
                        'ECIES); with RSA, OAEP. iOS/macOS keys always '
                        'decrypt.',
                    onChanged: busy
                        ? null
                        : (v) => c.update(() => c.enableDecryption = v),
                  ),
                  if (platform == DevicePlatform.android &&
                      c.enableDecryption &&
                      c.signatureType == SignatureType.ecdsa)
                    const CapabilityBanner(
                      title: 'Hybrid mode prompts at creation',
                      message: 'Creating a hybrid EC key shows a prompt even '
                          'without enforceBiometric (two with it): the '
                          'decryption key is wrapped by an auth-bound '
                          'keystore key.',
                    ),
                  OptionSwitch(
                    key: const ValueKey('keys.failIfExists'),
                    name: 'failIfExists',
                    platforms: allPlatforms,
                    value: c.failIfExists,
                    description: 'Return keyAlreadyExists instead of silently '
                        'replacing the key under this alias.',
                    onChanged:
                        busy ? null : (v) => c.update(() => c.failIfExists = v),
                  ),
                ],
              ),
            ),
            SectionCard(
              title: 'Prompt text',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  ArgTextField(
                    name: 'promptMessage',
                    platforms: allPlatforms,
                    controller: c.promptMessage,
                    helper: 'Title (Android) or reason (iOS/macOS/Windows) '
                        'of any prompt shown while creating the key.',
                  ),
                  ArgTextField(
                    name: 'config.promptSubtitle',
                    platforms: androidOnly,
                    controller: c.promptSubtitle,
                  ),
                  ArgTextField(
                    name: 'config.promptDescription',
                    platforms: androidOnly,
                    controller: c.promptDescription,
                  ),
                  ArgTextField(
                    name: 'config.cancelButtonText',
                    platforms: androidOnly,
                    controller: c.cancelButtonText,
                    hint: 'null → "Cancel"',
                  ),
                ],
              ),
            ),
            _AttestationOptions(controller: c, busy: busy),
            Align(
              alignment: Alignment.centerRight,
              child: RunButton(
                key: const ValueKey('keys.create'),
                label: 'createKeys',
                icon: Icons.key,
                busy: busy,
                onPressed: c.create,
              ),
            ),
            if (c.result != null) _KeyResult(controller: c),
            if (c.verifyingAttestation)
              const SectionCard(
                title: 'Attestation',
                child: Row(
                  children: [
                    SizedBox.square(
                      dimension: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                    SizedBox(width: 12),
                    Expanded(child: Text('Verifying the chain locally…')),
                  ],
                ),
              ),
            if (c.report != null) AttestationSection(report: c.report!),
          ],
        );
      },
    );
  }

  static String _signatureTypeHelp(DevicePlatform platform, SignatureType t) {
    final rsa = t == SignatureType.rsa;
    return switch (platform) {
      DevicePlatform.android => rsa
          ? 'RSA-2048 in the Android keystore; signs with PKCS#1 v1.5 / '
              'SHA-256, and decrypts (OAEP) with enableDecryption.'
          : 'EC P-256 in the TEE or StrongBox; signs with ECDSA / SHA-256. '
              'enableDecryption adds a separate ECIES key (hybrid mode).',
      DevicePlatform.ios || DevicePlatform.macos => rsa
          ? 'A software RSA-2048 key wrapped by a Secure Enclave key. It '
              'signs (PKCS#1 v1.5) and decrypts (OAEP SHA-256).'
          : 'A Secure Enclave P-256 key. It signs (ECDSA / SHA-256) and '
              'decrypts (Apple ECIES).',
      DevicePlatform.windows =>
        'Windows Hello always creates RSA-2048 keys (signatureType is '
            'ignored).',
      DevicePlatform.other => 'Not supported on this platform.',
    };
  }

  static String _keyFormatHelp(KeyFormat f) => switch (f) {
        KeyFormat.base64 => 'publicKey is the base64 SubjectPublicKeyInfo '
            '(SPKI) DER.',
        KeyFormat.pem => 'publicKey is SPKI DER in PEM armour '
            '(-----BEGIN PUBLIC KEY-----).',
        KeyFormat.hex => 'publicKey is the SPKI DER in hex.',
        KeyFormat.raw => 'raw: publicKey is still the base64 SPKI string; '
            'use publicKeyBytes for bytes.',
      };

  static String _publicKeyBytesLayout(DevicePlatform p, SignatureType t) {
    if (p == DevicePlatform.ios || p == DevicePlatform.macos) {
      return t == SignatureType.ecdsa
          ? 'On ${p.label} it is the X9.63 uncompressed point 04|X|Y '
              '(65 bytes), not SPKI. Verify against publicKey.'
          : 'On ${p.label} it is a PKCS#1 RSAPublicKey, not SPKI. Verify '
              'against publicKey.';
    }
    return 'On ${p.label} it is the same SPKI DER as publicKey.';
  }
}

class _AttestationOptions extends StatelessWidget {
  const _AttestationOptions({required this.controller, required this.busy});

  final KeysController controller;
  final bool busy;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    final state = c.state;
    final platform = state.platform;
    final windows = platform == DevicePlatform.windows;
    final android = platform == DevicePlatform.android;
    String label(int n) => switch (n) {
          0 => 'none',
          129 => '129 bytes (too long)',
          _ => '$n bytes',
        };
    return SectionCard(
      title: 'Hardware key attestation',
      subtitle: 'config.attestationChallenge (Uint8List, 1–128 bytes)',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const FieldLabel('config.attestationChallenge',
              platforms: androidOnly),
          const SizedBox(height: 8),
          if (windows)
            const CapabilityBanner(
              title: 'Not available on Windows',
              message: 'Windows key attestation is not implemented; a '
                  'challenge makes createKeys return notSupported. The Errors '
                  'screen has a one-tap trigger for that.',
            )
          else if (!android)
            CapabilityBanner(
              title: 'Android only',
              message: 'Apple has no public API to attest a single Secure '
                  'Enclave key. On ${platform.label} any challenge makes '
                  'createKeys return notSupported without touching existing '
                  'keys — pick a length to see it.',
            )
          else
            const Text(
              'A real server issues a random, single-use challenge and '
              'verifies the returned chain (leaf first) up to Google\'s '
              'roots. Here the Explorer makes the challenge itself. Needs '
              'Android 7+; if StrongBox fails the plugin retries in the TEE. '
              'In hybrid mode only the signing key is attested.',
            ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (final n in attestationChallengeLengths)
                ChoiceChip(
                  key: ValueKey('keys.attestation.$n'),
                  label: Text(label(n)),
                  selected: c.attestationLength == n,
                  onSelected: busy || (windows && n != 0)
                      ? null
                      : (_) => c.update(() => c.attestationLength = n),
                ),
            ],
          ),
          if (c.attestationLength == 129) ...[
            const SizedBox(height: 8),
            const Text('129 bytes is over the limit: createKeys returns '
                'invalidInput before touching any key.'),
          ],
        ],
      ),
    );
  }
}

class _KeyResult extends StatelessWidget {
  const _KeyResult({required this.controller});

  final KeysController controller;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    final state = c.state;
    final r = c.result!;
    final platform = state.platform;
    final ok = isSuccessCode(r.code);
    return ResultCard(
      key: const ValueKey('keys.result'),
      title: 'KeyCreationResult',
      subtitle: 'keyAlias: ${c.resultAlias?.label}',
      result: r,
      children: [
        if (r.publicKey != null)
          PublicKeySummary(publicKey: r.publicKey!, label: 'publicKey'),
        if (r.decryptingPublicKey != null)
          PublicKeySummary(
            publicKey: r.decryptingPublicKey!,
            label: 'decryptingPublicKey',
          ),
        if (r.publicKeyBytes != null)
          CheckRow(
            kind: StatusKind.info,
            title: 'publicKeyBytes on ${platform.label}',
            detail: KeysScreen._publicKeyBytesLayout(
              platform,
              r.algorithm?.toUpperCase().startsWith('EC') == true
                  ? SignatureType.ecdsa
                  : SignatureType.rsa,
            ),
          ),
        if (r.isHybridMode != null)
          CheckRow(
            kind: StatusKind.info,
            title: 'isHybridMode: ${r.isHybridMode}',
            detail: r.isHybridMode!
                ? 'Separate keys: the keystore key signs, a software EC key '
                    '(wrapped by a keystore AES key) decrypts. Encrypt to '
                    'decryptingPublicKey.'
                : 'One key signs and, where the platform allows, decrypts. '
                    'Encrypt to publicKey.',
          ),
        if (r.authenticationType != null)
          AuthTypeNote(
            type: r.authenticationType,
            silentKey: c.resultConfig?.requireAuthentication == false,
          ),
        if (ok) ...[
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              OutlinedButton.icon(
                onPressed: () => state.goTo(ExplorerDestination.sign),
                icon: const Icon(Icons.draw_outlined),
                label: const Text('Sign with it'),
              ),
              if (state.capabilities.supportsDecrypt)
                OutlinedButton.icon(
                  onPressed: () => state.goTo(ExplorerDestination.decrypt),
                  icon: const Icon(Icons.lock_open_outlined),
                  label: const Text('Decrypt with it'),
                ),
            ],
          ),
        ],
      ],
    );
  }
}

/// A locally inspected attestation report, clearly labelled as a demo.
class AttestationSection extends StatelessWidget {
  /// Creates the section.
  const AttestationSection({super.key, required this.report, this.note});

  /// The report.
  final AttestationReport report;

  /// Extra caveat shown in the banner.
  final String? note;

  @override
  Widget build(BuildContext context) {
    return Column(
      key: const ValueKey('attestation.section'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        CapabilityBanner(
          title: 'Local inspection (demo) — a real server issues the '
              'challenge and verifies',
          kind: StatusKind.warning,
          message: 'The app never decides whether its own key is trusted. '
              'This runs the same checks a server would, against Google\'s '
              'attestation roots (fetched $googleRootsFetchedOn), so you can '
              'see what the chain proves. Revocation is not checked.'
              '${note == null ? '' : '\n\n$note'}',
        ),
        const SizedBox(height: 12),
        AttestationReportView(report: report),
        if (report.certificates.isEmpty && report.chain.isNotEmpty)
          Align(
            alignment: Alignment.centerLeft,
            child: TextButton.icon(
              onPressed: () => copyToClipboard(context, report.chainPem,
                  what: 'Certificate chain'),
              icon: const Icon(Icons.copy),
              label: const Text('Copy chain as PEM'),
            ),
          ),
      ],
    );
  }
}
