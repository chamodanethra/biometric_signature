import 'dart:async';

import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../client/vault_controller.dart';
import '../models/sealed_item.dart';
import '../server/in_transit_tamper.dart';
import '../server/provisioning_server.dart';
import '../widgets/common.dart';

/// The server console tabs (opened from the terminal icon in the app bar):
/// server records, audit log, wire log, and faults / reset.
List<DevConsoleTab> serverConsoleTabs(VaultController controller) => [
      DevConsoleTab(
        label: 'Records',
        icon: Icons.storage,
        builder: (context) => _RecordsTab(controller: controller),
      ),
      DevConsoleTab(
        label: 'Audit',
        icon: Icons.fact_check_outlined,
        builder: (context) =>
            AuditLogView(log: controller.services.server.audit),
      ),
      DevConsoleTab(
        label: 'Wire',
        icon: Icons.swap_vert,
        builder: (context) => WireLogView(
          log: controller.services.transport.log,
          emptyText: 'No requests yet. Set up the vault or sync.',
        ),
      ),
      DevConsoleTab(
        label: 'Faults',
        icon: Icons.bug_report_outlined,
        builder: (context) => _FaultsTab(controller: controller),
      ),
    ];

class _RecordsTab extends StatefulWidget {
  const _RecordsTab({required this.controller});

  final VaultController controller;

  @override
  State<_RecordsTab> createState() => _RecordsTabState();
}

class _RecordsTabState extends State<_RecordsTab> {
  final _title = TextEditingController();
  final _value = TextEditingController();
  List<RegisteredDevice> _devices = const [];
  List<ServerSecret> _secrets = const [];

  ProvisioningServer get _server => widget.controller.services.server;

  @override
  void initState() {
    super.initState();
    _server.addListener(_reload);
    unawaited(_load());
  }

  void _reload() => unawaited(_load());

  Future<void> _load() async {
    final devices = await _server.devices();
    final secrets = await _server.secrets();
    if (!mounted) return;
    setState(() {
      _devices = devices;
      _secrets = secrets;
    });
  }

  @override
  void dispose() {
    _server.removeListener(_reload);
    _title.dispose();
    _value.dispose();
    super.dispose();
  }

  Future<void> _addSecret() async {
    final title = _title.text.trim();
    final value = _value.text;
    if (title.isEmpty || value.isEmpty) return;
    await _server.addSecret(title, value);
    _title.clear();
    _value.clear();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final myId = widget.controller.repo.deviceId;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const Caption(
            'Demo server: registration is not authenticated and data lives '
            'in SharedPreferences under "server.". See the README for what '
            'a real server must add.'),
        const SizedBox(height: 12),
        Text('Registered vault keys', style: theme.textTheme.titleSmall),
        if (_devices.isEmpty) const Caption('None yet.'),
        for (final d in _devices)
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  KeyValueRow(
                    label: 'Device',
                    value: d.deviceId == myId
                        ? '${d.deviceId} (this device)'
                        : d.deviceId,
                    copyable: false,
                  ),
                  KeyValueRow(
                      label: 'Platform',
                      value: d.platform.label,
                      copyable: false),
                  KeyValueRow(
                      label: 'Key',
                      value: '${d.algorithm} ${d.keySize ?? ''}'
                          '${d.isHybridMode ? ' (hybrid)' : ''}',
                      copyable: false),
                  KeyValueRow(
                      label: 'Seals with',
                      value: d.scheme.label,
                      copyable: false),
                  KeyValueRow(
                    label: 'Sealing key',
                    value: shortFingerprint(d.keyFingerprint),
                    monospace: true,
                    copyable: false,
                  ),
                  KeyValueRow(
                      label: 'Generation',
                      value: '${d.generation}',
                      copyable: false),
                  KeyValueRow(
                      label: 'Registered',
                      value: formatTimestamp(d.registeredAt),
                      copyable: false),
                ],
              ),
            ),
          ),
        const SizedBox(height: 16),
        Text('Server secrets', style: theme.textTheme.titleSmall),
        const Caption('The server keeps the plaintext so it can seal them '
            'again for a new key. Devices receive ciphertext only.'),
        for (final s in _secrets)
          ListTile(
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.key),
            title: Text(s.title),
            subtitle: Text('${s.value.length} characters'),
          ),
        const SizedBox(height: 8),
        TextField(
          controller: _title,
          decoration: const InputDecoration(labelText: 'New secret title'),
        ),
        const SizedBox(height: 8),
        TextField(
          controller: _value,
          decoration: const InputDecoration(labelText: 'Secret value'),
          minLines: 1,
          maxLines: 4,
        ),
        const SizedBox(height: 8),
        Align(
          alignment: Alignment.centerLeft,
          child: FilledButton.tonalIcon(
            onPressed: _addSecret,
            icon: const Icon(Icons.add),
            label: const Text('Add server secret'),
          ),
        ),
        const Caption('Devices receive it, sealed to their key, on the next '
            'sync.'),
      ],
    );
  }
}

class _FaultsTab extends StatelessWidget {
  const _FaultsTab({required this.controller});

  final VaultController controller;

  @override
  Widget build(BuildContext context) {
    final services = controller.services;
    final transport = services.transport;
    final tamper = services.tamper;
    return ListenableBuilder(
      listenable: Listenable.merge(
          [transport.asListenable, tamper.asListenable, controller]),
      builder: (context, _) {
        final theme = Theme.of(context);
        final pending = [
          if (tamper.armed != null) 'tamper ${tamper.armed!.label}',
          for (final f in transport.pendingFaults) f.label,
        ];
        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Text('Network faults', style: theme.textTheme.titleSmall),
            for (final target in TamperTarget.values)
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.flash_on_outlined),
                title: Text('Tamper with the next delivery: ${target.label}'),
                subtitle: Text(target == TamperTarget.devicePayload
                    ? 'decrypt() fails; the app checks the key, finds it '
                        'healthy, and blames the ciphertext.'
                    : 'decrypt() succeeds (you authenticate), then the '
                        'AES-GCM tag check rejects the content.'),
                trailing: tamper.armed == target
                    ? const StatusChip(label: 'Armed', kind: StatusKind.warning)
                    : null,
                onTap: () => tamper.arm(target),
              ),
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(Icons.cloud_off_outlined),
              title: const Text('Fail the next registration'),
              subtitle: const Text('The key is created on the device but the '
                  'server never hears of it. Setup offers a retry that '
                  're-reads the key with getKeyInfo.'),
              onTap: () => transport.failNext(ProvisioningServer.registerRoute),
            ),
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(Icons.sync_problem_outlined),
              title: const Text('Fail the next sync'),
              onTap: () => transport.failNext(ProvisioningServer.syncRoute),
            ),
            if (tamper.lastEvent != null)
              CapabilityBanner(
                kind: StatusKind.warning,
                title: 'Last tampering',
                message: '${tamper.lastEvent} Open the item and reveal it; '
                    'sync again to restore a good copy.',
              ),
            const SizedBox(height: 8),
            Text(
              pending.isEmpty
                  ? 'No pending faults.'
                  : 'Pending: '
                      '${pending.join('; ')}',
            ),
            if (pending.isNotEmpty)
              Align(
                alignment: Alignment.centerLeft,
                child: TextButton(
                  onPressed: () {
                    transport.clearFaults();
                    tamper.disarm();
                  },
                  child: const Text('Clear faults'),
                ),
              ),
            const Divider(height: 32),
            Text('Reset', style: theme.textTheme.titleSmall),
            const Caption('deleteAllKeys() removes every key this plugin '
                "created, then both the server's and the device's data are "
                'cleared.'),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerLeft,
              child: FilledButton.icon(
                style: FilledButton.styleFrom(
                  backgroundColor: theme.colorScheme.error,
                  foregroundColor: theme.colorScheme.onError,
                ),
                onPressed:
                    controller.busy != null ? null : () => _reset(context),
                icon: const Icon(Icons.restart_alt),
                label: const Text('Reset demo'),
              ),
            ),
          ],
        );
      },
    );
  }

  Future<void> _reset(BuildContext context) async {
    final navigator = Navigator.of(context);
    final ok = await confirmAction(
      context,
      title: 'Reset the demo?',
      message: 'Deletes the vault key (deleteAllKeys), every stored item and '
          'the server records. This cannot be undone.',
      confirmLabel: 'Reset',
    );
    if (!ok) return;
    navigator.popUntil((route) => route.isFirst);
    await controller.resetDemo();
  }
}
