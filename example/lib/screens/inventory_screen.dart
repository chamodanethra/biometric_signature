import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../state/controllers.dart';
import '../state/explorer_state.dart';
import '../state/key_alias.dart';
import '../state/result_fields.dart';
import '../widgets/alias_picker.dart';
import '../widgets/form_widgets.dart';
import '../widgets/result_card.dart';
import 'keys_screen.dart';

/// `getKeyInfo`, `biometricKeyExists`, `deleteKeys` and `deleteAllKeys`.
class InventoryScreen extends StatelessWidget {
  /// Creates the screen.
  const InventoryScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    final c = state.inventory;
    return ListenableBuilder(
      listenable: Listenable.merge([state, c]),
      builder: (context, _) {
        final refreshingAll = c.isBusy(InventoryController.refreshAllOp);
        return ScreenList(
          children: [
            const ScreenIntro(
              'The plugin cannot list aliases, so the Explorer probes a '
              'fixed set plus one custom alias. Use getKeyInfo on launch and '
              'after unexpected failures: it reports missing and invalidated '
              'keys without a prompt.',
            ),
            UnexpectedErrorBanner(controller: c),
            SectionCard(
              title: 'Options',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  OptionSwitch(
                    key: const ValueKey('inventory.checkValidity'),
                    name: 'checkValidity',
                    platforms: allPlatforms,
                    value: c.checkValidity,
                    description: 'Also report isValid (false after a '
                        'biometric enrollment change invalidated the key). '
                        'Always true on Windows.',
                    onChanged: (v) => c.update(() => c.checkValidity = v),
                  ),
                  EnumChoice<KeyFormat>(
                    key: const ValueKey('inventory.keyFormat'),
                    name: 'keyFormat',
                    platforms: allPlatforms,
                    values: KeyFormat.values,
                    selected: c.keyFormat,
                    onChanged: (v) => c.update(() => c.keyFormat = v),
                  ),
                  const SizedBox(height: 8),
                  const ProbeAliasField(),
                  const SizedBox(height: 12),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: RunButton(
                      key: const ValueKey('inventory.refreshAll'),
                      label: 'getKeyInfo for all',
                      icon: Icons.refresh,
                      busy: refreshingAll,
                      onPressed: c.refreshAll,
                    ),
                  ),
                ],
              ),
            ),
            for (final alias in state.aliasOptions)
              _AliasCard(controller: c, alias: alias),
            SectionCard(
              title: 'deleteAllKeys()',
              subtitle: 'Every key this plugin manages, under every alias',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  if (c.deleteAllResult != null)
                    KeyValueRow(
                      label: 'result',
                      value: '${c.deleteAllResult}',
                      copyable: false,
                    ),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: RunButton(
                      key: const ValueKey('inventory.deleteAll'),
                      label: 'deleteAllKeys',
                      icon: Icons.delete_forever,
                      busy: c.isBusy(InventoryController.deleteAllOp),
                      onPressed: () => _confirmDeleteAll(context, c),
                    ),
                  ),
                ],
              ),
            ),
          ],
        );
      },
    );
  }

  static Future<void> _confirmDeleteAll(
      BuildContext context, InventoryController c) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        icon: const Icon(Icons.warning_amber_rounded),
        title: const Text('Delete every key?'),
        content: const Text(
          'deleteAllKeys removes the key material of every alias managed by '
          'this plugin in this app — including aliases the Explorer does '
          'not know about. Servers that registered those public keys will '
          'no longer receive valid signatures.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const ValueKey('inventory.deleteAll.confirm'),
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Delete all'),
          ),
        ],
      ),
    );
    if (confirmed == true) await c.deleteAll();
  }
}

class _AliasCard extends StatelessWidget {
  const _AliasCard({required this.controller, required this.alias});

  final InventoryController controller;
  final KeyAlias alias;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    final state = c.state;
    final info = c.infos[alias];
    final exists = c.existsResults[alias];
    final deleted = c.deleteResults[alias];
    final record = state.recordFor(alias);
    final chain = info?.attestationCertificateChain;
    final StatusChip status;
    if (info == null) {
      status = const StatusChip(label: 'not read', kind: StatusKind.neutral);
    } else if (info.exists != true) {
      status = const StatusChip(label: 'no key', kind: StatusKind.neutral);
    } else if (info.isValid == false) {
      status = const StatusChip(label: 'invalidated', kind: StatusKind.danger);
    } else {
      status = const StatusChip(label: 'key present', kind: StatusKind.success);
    }
    return SectionCard(
      key: ValueKey('inventory.alias.${alias.label}'),
      title: alias.isDefault ? 'Default alias (keyAlias: null)' : alias.label,
      subtitle: record == null
          ? null
          : 'Created in this session (${record.result.algorithm ?? '?'}'
              '${record.isSilent ? ', silent' : ''})',
      trailing: status,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (info != null) ...[
            for (final f in resultFields(info)) ResultFieldRow(field: f),
            if (chain != null && chain.isNotEmpty) ...[
              const SizedBox(height: 8),
              Align(
                alignment: Alignment.centerLeft,
                child: OutlinedButton.icon(
                  key: ValueKey('inventory.inspect.${alias.label}'),
                  icon: const Icon(Icons.policy_outlined),
                  label: Text('Inspect ${chain.length}-certificate chain'),
                  onPressed: () => Navigator.of(context).push(
                    MaterialPageRoute<void>(
                      builder: (_) => AttestationInspectPage(
                        inspector: state.inspectAttestation,
                        alias: alias,
                        chain: chain,
                        challenge: record?.attestationChallenge,
                        publicKey: info.publicKey ?? record?.result.publicKey,
                      ),
                    ),
                  ),
                ),
              ),
            ],
            const SizedBox(height: 8),
          ],
          if (exists != null)
            KeyValueRow(
              label: 'biometricKeyExists',
              value: '${exists.$1} (checkValidity: ${exists.$2})',
              copyable: false,
            ),
          if (deleted != null)
            KeyValueRow(
              label: 'deleteKeys',
              value: '$deleted',
              copyable: false,
            ),
          const SizedBox(height: 4),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              RunButton(
                key: ValueKey('inventory.info.${alias.label}'),
                label: 'getKeyInfo',
                icon: Icons.info_outline,
                tonal: true,
                busy: c.isBusy(InventoryController.infoOp(alias)),
                onPressed: () => c.refresh(alias),
              ),
              RunButton(
                key: ValueKey('inventory.exists.${alias.label}'),
                label: 'biometricKeyExists',
                icon: Icons.help_outline,
                tonal: true,
                busy: c.isBusy(InventoryController.existsOp(alias)),
                onPressed: () => c.checkExists(alias),
              ),
              RunButton(
                key: ValueKey('inventory.delete.${alias.label}'),
                label: 'deleteKeys',
                icon: Icons.delete_outline,
                tonal: true,
                busy: c.isBusy(InventoryController.deleteOp(alias)),
                onPressed: () => c.delete(alias),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

/// Inspects the attestation chain `getKeyInfo` returned for an alias.
class AttestationInspectPage extends StatefulWidget {
  /// Creates the page.
  const AttestationInspectPage({
    super.key,
    required this.inspector,
    required this.alias,
    required this.chain,
    required this.challenge,
    required this.publicKey,
  });

  /// Verifier.
  final AttestationInspector inspector;

  /// Alias.
  final KeyAlias alias;

  /// Chain from getKeyInfo.
  final List<Uint8List> chain;

  /// The challenge sent at creation, if created in this session.
  final Uint8List? challenge;

  /// The key's public key.
  final String? publicKey;

  @override
  State<AttestationInspectPage> createState() => _AttestationInspectPageState();
}

class _AttestationInspectPageState extends State<AttestationInspectPage> {
  late final Future<AttestationReport> _report = widget.inspector(
    chain: widget.chain,
    // Without the original challenge the challenge check must fail, which
    // is exactly what a server does with an attestation it did not ask for.
    expectedChallenge: widget.challenge ?? Uint8List(0),
    expectedPublicKey: widget.publicKey ?? '',
  );

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Attestation · ${widget.alias.label}')),
      body: FutureBuilder<AttestationReport>(
        future: _report,
        builder: (context, snapshot) {
          if (snapshot.hasError) {
            return ScreenList(children: [
              CapabilityBanner(
                title: 'Inspection failed',
                message: '${snapshot.error}',
                kind: StatusKind.danger,
              ),
            ]);
          }
          if (!snapshot.hasData) {
            return const Center(child: CircularProgressIndicator());
          }
          return ScreenList(children: [
            AttestationSection(
              report: snapshot.data!,
              note: widget.challenge == null
                  ? 'This key was not created in this session, so the '
                      'Explorer does not know the challenge it was attested '
                      'with: "Challenge matches" fails, as it would on a '
                      'server that never issued it.'
                  : 'Checked against the challenge sent when the key was '
                      'created in this session.',
            ),
          ]);
        },
      ),
    );
  }
}
