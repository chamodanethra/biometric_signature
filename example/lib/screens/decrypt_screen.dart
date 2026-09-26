import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../state/controllers.dart';
import '../state/explorer_state.dart';
import '../state/result_fields.dart';
import '../widgets/alias_picker.dart';
import '../widgets/form_widgets.dart';
import '../widgets/result_card.dart';

/// `decrypt`, with the encryption scheme derived from the actual key.
class DecryptScreen extends StatelessWidget {
  /// Creates the screen.
  const DecryptScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    final c = state.decrypt;
    return ListenableBuilder(
      listenable: Listenable.merge([state, c]),
      builder: (context, _) {
        final caps = state.capabilities;
        final decryptBusy = c.isBusy(DecryptController.decryptOp);
        return ScreenList(
          children: [
            const ScreenIntro(
              'Anyone with the public key (usually your server) encrypts; '
              'only the device can decrypt, after authentication. The '
              'encryption scheme depends on the platform and on how the key '
              'was created, so the Explorer derives it from the key itself '
              'instead of offering a toggle. decrypt() returns UTF-8 text.',
            ),
            if (!caps.supportsDecrypt)
              CapabilityBanner(
                key: const ValueKey('decrypt.unsupported'),
                title: 'decrypt() is not available on '
                    '${state.platform.label}',
                kind: StatusKind.warning,
                message: 'Windows Hello keys can only sign: decrypt() '
                    'returns notAvailable. Encryption is disabled here.',
                action: RunButton(
                  key: const ValueKey('decrypt.anyway'),
                  label: 'Call decrypt() anyway',
                  tonal: true,
                  busy: decryptBusy,
                  onPressed: c.decryptAnyway,
                ),
              ),
            UnexpectedErrorBanner(controller: c),
            const SectionCard(
              title: 'Alias',
              child: AliasPicker(showProbeField: false),
            ),
            if (caps.supportsDecrypt) ...[
              _SchemeCard(controller: c),
              _CiphertextCard(controller: c),
              _DecryptOptions(controller: c),
              Align(
                alignment: Alignment.centerRight,
                child: RunButton(
                  key: const ValueKey('decrypt.run'),
                  label: 'decrypt',
                  icon: Icons.lock_open,
                  busy: decryptBusy,
                  onPressed: c.canDecrypt ? c.decrypt : null,
                ),
              ),
            ],
            if (c.result != null) _DecryptResult(controller: c),
          ],
        );
      },
    );
  }
}

class _SchemeCard extends StatelessWidget {
  const _SchemeCard({required this.controller});

  final DecryptController controller;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    final scheme = c.schemeIsCurrent ? c.scheme : null;
    final info = c.schemeIsCurrent ? c.keyInfo : null;
    return SectionCard(
      title: 'Encryption scheme',
      subtitle: 'EncryptionTarget.resolve(platform, getKeyInfo(alias))',
      trailing: RunButton(
        key: const ValueKey('decrypt.resolve'),
        label: 'Read key',
        icon: Icons.manage_search,
        tonal: true,
        busy: c.isBusy(DecryptController.resolveOp),
        onPressed: c.resolveScheme,
      ),
      child: scheme == null
          ? Text('Tap "Read key" (or "Encrypt") to call getKeyInfo for '
              '${aliasPhrase(c.state.selectedAlias)} and pick the scheme.')
          : Column(
              key: const ValueKey('decrypt.scheme'),
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                CheckRow(
                  kind: scheme.isSupported
                      ? StatusKind.success
                      : StatusKind.warning,
                  title: scheme.label,
                  detail: scheme.description,
                ),
                if (info != null)
                  KeyValueRow(
                    label: 'getKeyInfo',
                    value: 'exists: ${info.exists}, algorithm: '
                        '${info.algorithm}, isHybridMode: '
                        '${info.isHybridMode}',
                    copyable: false,
                  ),
                if (c.schemeNotes.isNotEmpty) NoteList(c.schemeNotes),
              ],
            ),
    );
  }
}

class _CiphertextCard extends StatelessWidget {
  const _CiphertextCard({required this.controller});

  final DecryptController controller;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    final encryptBusy = c.isBusy(DecryptController.encryptOp);
    final ct = c.ciphertextIsCurrent ? c.ciphertext : null;
    final bytes = c.plaintextBytes;
    final rsa = c.schemeIsCurrent && c.scheme is RsaOaepScheme;
    return SectionCard(
      title: 'Ciphertext',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          EnumChoice<DecryptSource>(
            key: const ValueKey('decrypt.source'),
            name: 'source',
            values: DecryptSource.values,
            selected: c.source,
            labelOf: (s) => s == DecryptSource.encryptHere
                ? 'Encrypt here'
                : 'Paste ciphertext',
            onChanged: (s) => c.update(() => c.source = s),
          ),
          if (c.source == DecryptSource.encryptHere) ...[
            ArgTextField(
              key: const ValueKey('decrypt.plaintext'),
              name: 'plaintext (UTF-8)',
              controller: c.plaintext,
              maxLines: 3,
              helper: '$bytes bytes'
                  '${rsa ? ' · RSA-OAEP limit $rsaOaepMaxPlaintextBytes' : ''}',
              errorText: c.overRsaLimit
                  ? 'Over the RSA-2048 OAEP limit of '
                      '$rsaOaepMaxPlaintextBytes bytes'
                  : null,
              onChanged: (_) => c.update(() {}),
            ),
            Align(
              alignment: Alignment.centerLeft,
              child: RunButton(
                key: const ValueKey('decrypt.encrypt'),
                label: 'Encrypt locally',
                icon: Icons.lock_outline,
                tonal: true,
                busy: encryptBusy,
                onPressed: c.overRsaLimit ? null : c.encrypt,
              ),
            ),
            if (c.encryptError != null) ...[
              const SizedBox(height: 8),
              CapabilityBanner(
                title: 'Not encrypted',
                message: c.encryptError!,
                kind: StatusKind.warning,
              ),
            ],
            if (c.schemeIsCurrent && c.scheme?.isSupported == false) ...[
              const SizedBox(height: 8),
              CapabilityBanner(
                title: 'This key cannot decrypt',
                message: c.scheme!.description,
                kind: StatusKind.warning,
              ),
            ],
            if (ct != null) ...[
              const SizedBox(height: 12),
              MonoBlock(
                label: 'Ciphertext (${ct.length} bytes, base64)',
                text: c.payloadFor(PayloadFormat.base64)!,
                maxHeight: 140,
              ),
            ],
          ] else
            ArgTextField(
              key: const ValueKey('decrypt.pasted'),
              name: 'payload (String)',
              controller: c.pasted,
              monospace: true,
              maxLines: 5,
              hint: 'Ciphertext produced for this key, in the payload format '
                  'selected below',
              helper: 'Sent verbatim with the payloadFormat below.',
              onChanged: (_) => c.update(() {}),
            ),
        ],
      ),
    );
  }
}

class _DecryptOptions extends StatelessWidget {
  const _DecryptOptions({required this.controller});

  final DecryptController controller;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    final busy = c.isBusy(DecryptController.decryptOp);
    return SectionCard(
      title: 'decrypt() arguments',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          EnumChoice<PayloadFormat>(
            key: const ValueKey('decrypt.payloadFormat'),
            name: 'payloadFormat',
            platforms: mobileAndMac,
            values: PayloadFormat.values,
            selected: c.payloadFormat,
            onChanged: busy ? null : (v) => c.update(() => c.payloadFormat = v),
            description: switch (c.payloadFormat) {
              PayloadFormat.base64 => 'payload is base64 ciphertext.',
              PayloadFormat.hex => 'payload is hex ciphertext.',
              PayloadFormat.raw => 'raw is base64-decoded natively on every '
                  'platform (it is not "UTF-8 bytes"), so the Explorer sends '
                  'base64 text for it too.',
            },
          ),
          if (c.source == DecryptSource.encryptHere &&
              c.ciphertextIsCurrent) ...[
            MonoBlock(
              label: 'payload to send',
              text: c.payloadFor(c.payloadFormat)!,
              maxHeight: 120,
            ),
            const SizedBox(height: 8),
          ],
          ArgTextField(
            name: 'promptMessage',
            platforms: mobileAndMac,
            controller: c.promptMessage,
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
          ),
          OptionSwitch(
            key: const ValueKey('decrypt.allowDeviceCredentials'),
            name: 'config.allowDeviceCredentials',
            platforms: androidOnly,
            value: c.allowDeviceCredentials,
            description: 'Offer the device PIN/pattern in the prompt (the key '
                'must allow it).',
            onChanged: busy
                ? null
                : (v) => c.update(() => c.allowDeviceCredentials = v),
          ),
        ],
      ),
    );
  }
}

class _DecryptResult extends StatelessWidget {
  const _DecryptResult({required this.controller});

  final DecryptController controller;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    final r = c.result!;
    final expected = c.expectedPlaintext;
    final record = c.state.recordFor(c.state.selectedAlias);
    return ResultCard(
      key: const ValueKey('decrypt.result'),
      title: 'DecryptResult',
      subtitle: 'payloadFormat: ${c.sentFormat?.name}',
      result: r,
      children: [
        if (isSuccessCode(r.code) && expected != null)
          CheckRow(
            key: const ValueKey('decrypt.roundtrip'),
            kind: r.decryptedData == expected
                ? StatusKind.success
                : StatusKind.danger,
            title: r.decryptedData == expected
                ? 'Round trip OK: decryptedData equals the plaintext'
                : 'decryptedData differs from the plaintext',
          ),
        if (r.authenticationType != null)
          AuthTypeNote(
            type: r.authenticationType,
            silentKey: record?.isSilent == true,
          ),
      ],
    );
  }
}
