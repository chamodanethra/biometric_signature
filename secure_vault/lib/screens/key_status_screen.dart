import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/vault_controller.dart';
import '../models/sealed_item.dart';
import '../widgets/common.dart';

class _KeyStatus {
  const _KeyStatus(this.health, this.existsAndValid);

  final KeyHealth health;
  final bool existsAndValid;
}

/// The vault key as the plugin reports it, next to what the server
/// registered; re-provisioning lives here.
class KeyStatusScreen extends StatefulWidget {
  /// Creates the screen.
  const KeyStatusScreen({super.key});

  @override
  State<KeyStatusScreen> createState() => _KeyStatusScreenState();
}

class _KeyStatusScreenState extends State<KeyStatusScreen> {
  Future<_KeyStatus>? _status;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _status ??= _load();
  }

  Future<_KeyStatus> _load() async {
    final controller = AppScope.read(context);
    final health = await controller.refreshKeyHealth();
    final existsAndValid = await controller.keys.existsAndValid();
    return _KeyStatus(health, existsAndValid);
  }

  void _refresh() => setState(() => _status = _load());

  Future<void> _reprovision() async {
    final controller = AppScope.read(context);
    final messenger = ScaffoldMessenger.of(context);
    final ok = await confirmAction(
      context,
      title: 'Re-provision the vault key?',
      message: 'deleteKeys(keyAlias: "vault"), then createKeys and a new '
          'registration. The server re-seals its secrets to the new key. '
          'Notes and shared items sealed to the old key become unreadable '
          'forever.',
      confirmLabel: 'Re-provision',
    );
    if (!ok) return;
    final outcome = await controller.reprovision();
    showSnack(
        messenger,
        switch (outcome) {
          Provisioned(
            :final generation,
            :final itemsReceived,
            :final syncError
          ) =>
            syncError == null
                ? 'Generation $generation registered; $itemsReceived server '
                    'secrets re-sealed.'
                : 'Generation $generation registered, but the sync failed: '
                    '$syncError',
          KeyCreationFailed(:final code) =>
            'Key creation failed: ${guidanceFor(code).title} (${code.name}).',
          RegistrationFailed(:final message) => 'Registration failed: $message',
        });
    if (mounted) _refresh();
  }

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('Vault key'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Check again',
            onPressed: _refresh,
          ),
        ],
      ),
      body: ListenableBuilder(
        listenable: controller,
        builder: (context, _) => FutureBuilder<_KeyStatus>(
          future: _status,
          builder: (context, snapshot) {
            final status = snapshot.data;
            if (status == null) {
              return Center(
                child: snapshot.hasError
                    ? Text('${snapshot.error}')
                    : const CircularProgressIndicator(),
              );
            }
            return PageBody(children: [
              _healthCard(controller, status),
              _infoCard(status.health.info),
              _registrationCard(controller),
              _platformCard(controller),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  FilledButton.icon(
                    onPressed: controller.busy == null ? _reprovision : null,
                    icon: const Icon(Icons.autorenew),
                    label: Text(controller.busy ?? 'Re-provision vault key'),
                  ),
                  OutlinedButton.icon(
                    onPressed: _refresh,
                    icon: const Icon(Icons.refresh),
                    label: const Text('Check again'),
                  ),
                ],
              ),
            ]);
          },
        ),
      ),
    );
  }

  Widget _healthCard(VaultController controller, _KeyStatus status) {
    final health = status.health;
    final kind = switch (health.status) {
      KeyHealthStatus.healthy => StatusKind.success,
      KeyHealthStatus.invalidated ||
      KeyHealthStatus.missing =>
        StatusKind.danger,
    };
    final replaced = controller.keyState == VaultKeyState.replaced;
    return SectionCard(
      title: 'Health',
      trailing: keyStateChip(controller.keyState),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          CheckRow(
            kind: kind,
            title: health.summary,
            detail: 'probeKey → getKeyInfo(keyAlias: "vault", '
                'checkValidity: true)',
          ),
          CheckRow(
            kind:
                status.existsAndValid ? StatusKind.success : StatusKind.danger,
            title: 'biometricKeyExists(checkValidity: true) → '
                '${status.existsAndValid}',
          ),
          if (health.status == KeyHealthStatus.healthy)
            CheckRow(
              kind: replaced ? StatusKind.warning : StatusKind.success,
              title: replaced
                  ? 'Not the key registered with the server'
                  : 'Matches the key registered with the server',
            ),
          if (health.status == KeyHealthStatus.invalidated) ...[
            const SizedBox(height: 8),
            const CapabilityBanner(
              kind: StatusKind.danger,
              title: 'Invalidated keys never come back',
              message: 'Adding or removing a fingerprint or face disabled '
                  'this key (setInvalidatedByBiometricEnrollment: true). '
                  'decrypt() now returns keyInvalidated. Re-provision below.',
            ),
          ],
        ],
      ),
    );
  }

  Widget _infoCard(KeyInfo info) {
    String fingerprintOf(String? key) {
      if (key == null) return '';
      try {
        return shortFingerprint(ParsedPublicKey.parse(key).fingerprint);
      } on FormatException {
        return 'unparseable';
      }
    }

    String show(Object? v) => v == null ? '' : '$v';
    return SectionCard(
      title: 'getKeyInfo',
      subtitle: 'What the plugin reports for alias "vault"',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          KeyValueRow(
              label: 'exists', value: show(info.exists), copyable: false),
          KeyValueRow(
              label: 'isValid', value: show(info.isValid), copyable: false),
          KeyValueRow(
              label: 'algorithm', value: show(info.algorithm), copyable: false),
          KeyValueRow(
              label: 'keySize', value: show(info.keySize), copyable: false),
          KeyValueRow(
              label: 'isHybridMode',
              value: show(info.isHybridMode),
              copyable: false),
          KeyValueRow(
            label: 'publicKey fingerprint',
            value: fingerprintOf(info.publicKey),
            monospace: true,
            copyable: false,
          ),
          if (info.decryptingPublicKey != null) ...[
            KeyValueRow(
                label: 'decryptingAlgorithm',
                value: show(info.decryptingAlgorithm),
                copyable: false),
            KeyValueRow(
                label: 'decryptingKeySize',
                value: show(info.decryptingKeySize),
                copyable: false),
            KeyValueRow(
              label: 'decryptingPublicKey fingerprint',
              value: fingerprintOf(info.decryptingPublicKey),
              monospace: true,
              copyable: false,
            ),
          ],
          if (info.isHybridMode == true)
            const Caption('Hybrid mode: the hardware EC key signs; the '
                'separate software EC key (wrapped by a biometric-bound '
                'keystore AES key) decrypts. Only the signing key could be '
                'covered by key attestation.'),
        ],
      ),
    );
  }

  Widget _registrationCard(VaultController controller) {
    final record = controller.record;
    if (record == null) {
      return const CapabilityBanner(
        title: 'Not registered',
        message: 'This device has no registered vault key.',
      );
    }
    return SectionCard(
      title: 'Registered with the server',
      subtitle: 'Generation ${record.generation} · '
          '${formatTimestamp(record.registeredAt)}',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          KeyValueRow(
              label: 'Scheme', value: record.scheme.label, copyable: false),
          Caption(record.scheme.description),
          KeyValueRow(
            label: 'Sealing key',
            value: shortFingerprint(record.encryptionKeyFingerprint),
            monospace: true,
            copyable: false,
          ),
          KeyValueRow(
            label: 'Device PIN / passcode',
            value: record.useDeviceCredentials
                ? 'Accepted (useDeviceCredentials)'
                : 'Biometrics only',
            copyable: false,
          ),
          KeyValueRow(label: 'Device id', value: record.deviceId),
        ],
      ),
    );
  }

  Widget _platformCard(VaultController controller) {
    final caps = controller.capabilities;
    return SectionCard(
      title: 'On ${controller.platform.label}',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          for (final note in caps.notes)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 2),
              child: Text('• $note'),
            ),
          if (caps.supportsEnrollmentInvalidation)
            const Padding(
              padding: EdgeInsets.only(top: 4),
              child: Caption('To see crypto-shredding: add a fingerprint or '
                  'face in system settings, come back and reveal an item.'),
            ),
        ],
      ),
    );
  }
}
