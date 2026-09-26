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

/// `createSignature` and `createSignatureFromBytes`, plus local verification.
class SignScreen extends StatelessWidget {
  /// Creates the screen.
  const SignScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    final c = state.sign;
    return ListenableBuilder(
      listenable: Listenable.merge([state, c]),
      builder: (context, _) {
        final busy = c.isBusy(SignController.signOp);
        final method = c.mode == SignMode.text
            ? 'createSignature'
            : 'createSignatureFromBytes';
        final record = state.recordFor(state.selectedAlias);
        return ScreenList(
          children: [
            const ScreenIntro(
              'Signing proves possession of the private key (and, for '
              'auth-bound keys, a fresh authentication). In a real flow the '
              'server sends a single-use nonce, the app signs its exact '
              'bytes, and the server verifies with the public key it stored '
              'at registration.',
            ),
            UnexpectedErrorBanner(controller: c),
            SectionCard(
              title: 'Alias',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const AliasPicker(showProbeField: false),
                  if (record?.isSilent == true) ...[
                    const SizedBox(height: 8),
                    CapabilityBanner(
                      title: 'Silent key',
                      message: state.capabilities.silentKeysPrompt
                          ? 'Windows Hello prompts anyway.'
                          : 'This key was created with requireAuthentication: '
                              'false, so signing will not prompt.',
                    ),
                  ],
                ],
              ),
            ),
            SectionCard(
              title: 'Payload',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  EnumChoice<SignMode>(
                    key: const ValueKey('sign.mode'),
                    name: 'method',
                    values: SignMode.values,
                    selected: c.mode,
                    labelOf: (m) => m == SignMode.text
                        ? 'createSignature (text)'
                        : 'createSignatureFromBytes',
                    onChanged: busy ? null : (m) => c.update(() => c.mode = m),
                    description: c.mode == SignMode.text
                        ? 'Signs the UTF-8 bytes of a string. The server '
                            'must verify over exactly the same bytes.'
                        : 'Signs raw bytes — the right choice for server '
                            'nonces and canonical payloads.',
                  ),
                  if (c.mode == SignMode.text)
                    ArgTextField(
                      key: const ValueKey('sign.text'),
                      name: 'payload (String)',
                      controller: c.textPayload,
                      maxLines: 3,
                      hint: 'Empty: invalidInput on Android and Windows',
                      onChanged: (_) => c.update(() {}),
                    )
                  else
                    _BytesPayload(controller: c, busy: busy),
                ],
              ),
            ),
            SectionCard(
              title: 'Output formats',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  EnumChoice<SignatureFormat>(
                    key: const ValueKey('sign.signatureFormat'),
                    name: 'signatureFormat',
                    platforms: allPlatforms,
                    values: SignatureFormat.values,
                    selected: c.signatureFormat,
                    onChanged: busy
                        ? null
                        : (v) => c.update(() => c.signatureFormat = v),
                    description: 'Encoding of result.signature. signatureBytes '
                        'always carries the raw bytes (with raw, signature '
                        'is base64). RSA: PKCS#1 v1.5 / SHA-256; EC: DER '
                        'ECDSA / SHA-256 (high S is possible — accept it).',
                  ),
                  EnumChoice<KeyFormat>(
                    key: const ValueKey('sign.keyFormat'),
                    name: 'keyFormat',
                    platforms: allPlatforms,
                    values: KeyFormat.values,
                    selected: c.keyFormat,
                    onChanged:
                        busy ? null : (v) => c.update(() => c.keyFormat = v),
                    description: 'Encoding of result.publicKey.',
                  ),
                ],
              ),
            ),
            SectionCard(
              title: 'Prompt',
              subtitle: 'promptMessage and CreateSignatureConfig',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  ArgTextField(
                    name: 'promptMessage',
                    platforms: allPlatforms,
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
                    key: const ValueKey('sign.allowDeviceCredentials'),
                    name: 'config.allowDeviceCredentials',
                    platforms: androidOnly,
                    value: c.allowDeviceCredentials,
                    description: 'Offer the device PIN/pattern in the prompt. '
                        'Only works if the key allows it '
                        '(useDeviceCredentials at creation).',
                    onChanged: busy
                        ? null
                        : (v) => c.update(() => c.allowDeviceCredentials = v),
                  ),
                ],
              ),
            ),
            Align(
              alignment: Alignment.centerRight,
              child: RunButton(
                key: const ValueKey('sign.run'),
                label: method,
                icon: Icons.draw,
                busy: busy,
                onPressed: c.canSign ? c.sign : null,
              ),
            ),
            if (c.result != null) _SignResult(controller: c),
          ],
        );
      },
    );
  }
}

class _BytesPayload extends StatelessWidget {
  const _BytesPayload({required this.controller, required this.busy});

  final SignController controller;
  final bool busy;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        EnumChoice<BytesSource>(
          key: const ValueKey('sign.bytesSource'),
          name: 'payload (Uint8List)',
          values: BytesSource.values,
          selected: c.bytesSource,
          labelOf: (s) =>
              s == BytesSource.randomNonce ? 'Random 32-byte nonce' : 'Hex',
          onChanged: busy ? null : (s) => c.update(() => c.bytesSource = s),
        ),
        if (c.bytesSource == BytesSource.randomNonce)
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: MonoBlock(
                  label: 'Nonce (stand-in for a server challenge)',
                  text: toHex(c.nonce),
                ),
              ),
              IconButton(
                tooltip: 'New nonce',
                onPressed: busy ? null : c.regenerateNonce,
                icon: const Icon(Icons.casino_outlined),
              ),
            ],
          )
        else
          ArgTextField(
            key: const ValueKey('sign.hex'),
            name: 'hex',
            controller: c.hexPayload,
            monospace: true,
            maxLines: 3,
            errorText: c.hexError,
            helper: 'Empty hex sends an empty payload (invalidInput).',
            hint: 'e.g. 00112233',
            onChanged: (_) => c.update(() {}),
          ),
      ],
    );
  }
}

class _SignResult extends StatelessWidget {
  const _SignResult({required this.controller});

  final SignController controller;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    final state = c.state;
    final r = c.result!;
    final ok = isSuccessCode(r.code);
    final alias = c.resultAlias;
    final record = alias == null ? null : state.recordFor(alias);
    final checks = c.verification;
    return ResultCard(
      key: const ValueKey('sign.result'),
      title: 'SignatureResult',
      subtitle:
          '${c.resultMode == SignMode.text ? 'createSignature' : 'createSignatureFromBytes'}'
          ' · keyAlias: ${alias?.label}',
      result: r,
      children: [
        if (c.signedMessage != null)
          KeyValueRow(
            label: 'signed bytes',
            value: describeBytes(c.signedMessage!, previewBytes: 32),
            monospace: true,
            copyable: false,
          ),
        if (r.authenticationType != null)
          AuthTypeNote(
            type: r.authenticationType,
            silentKey: record?.isSilent == true,
          ),
        if (ok) ...[
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              FilledButton.tonalIcon(
                key: const ValueKey('sign.verify'),
                onPressed: c.verify,
                icon: const Icon(Icons.verified_outlined),
                label: const Text('Verify locally'),
              ),
              const StatusChip(
                label: 'demo only — verify on your server',
                kind: StatusKind.warning,
              ),
            ],
          ),
        ],
        if (checks != null) ...[
          const SizedBox(height: 8),
          if (checks.isEmpty)
            const Text('No public key to verify against.')
          else
            for (final check in checks)
              CheckRow(
                kind: check.asExpected ? StatusKind.success : StatusKind.danger,
                title: check.title,
                detail: check.outcome.message,
              ),
          if (record == null)
            const Text(
              'This alias has no createKeys result in this session, so only '
              'the key returned with the signature was used. A server always '
              'verifies against the key it stored at registration.',
            ),
        ],
      ],
    );
  }
}
