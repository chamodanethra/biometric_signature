import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../app.dart';
import '../client/bank_client.dart';
import '../client/key_setup.dart';
import '../server/models.dart';
import '../widgets/bank_widgets.dart';

/// Re-verification: the silent device key proves the device, a one-time
/// code proves the person, and a new attested approval key replaces the old
/// one at the bank.
class ReverifyScreen extends StatefulWidget {
  /// Creates the screen.
  const ReverifyScreen({
    super.key,
    required this.reason,
    required this.explanation,
  });

  /// Reason recorded by the bank (`keyInvalidated`, `rotation` …).
  final String reason;

  /// Why the user is here.
  final String explanation;

  @override
  State<ReverifyScreen> createState() => _ReverifyScreenState();
}

class _ReverifyScreenState extends State<ReverifyScreen> {
  final _otp = TextEditingController();
  ApprovalKeyReverification? _attempt;
  late bool _allowDeviceCredential;
  bool _skipAttestation = false;
  String? _step;
  Object? _error;
  KeyRegistrationResult? _result;

  bool get _busy => _step != null;

  @override
  void initState() {
    super.initState();
    _allowDeviceCredential =
        AppScope.of(context).session.enrollment?.allowDeviceCredential ?? false;
    _otp.addListener(() => setState(() {}));
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
    } on BankError catch (e) {
      if (e.kind == BankErrorKind.signing &&
          e.code == BiometricError.keyNotFound) {
        if (!mounted) return;
        final services = AppScope.of(context);
        await services.session.bindingLost('The device-binding key is '
            'missing, so the bank cannot re-verify this device. Bind it '
            'again.');
        services.navigatorKey.currentState?.popUntil((r) => r.isFirst);
        return;
      }
      if (mounted) setState(() => _error = e);
    } catch (e) {
      if (mounted) setState(() => _error = e);
    } finally {
      if (mounted) setState(() => _step = null);
    }
  }

  Future<void> _sendCode() =>
      _run('Signing a request with device_binding…', () async {
        final services = AppScope.of(context);
        final attempt = _attempt ??= ApprovalKeyReverification(
          keys: services.keys,
          client: services.client,
          reason: widget.reason,
        );
        _otp.clear();
        await attempt.begin();
        if (mounted) setState(() {});
      });

  Future<void> _finish() async {
    final attempt = _attempt;
    if (attempt == null) return;
    final services = AppScope.of(context);
    await _run('Creating a new approval key…', () async {
      final result = await attempt.complete(
        otp: _otp.text,
        allowDeviceCredential: _allowDeviceCredential,
        skipAttestation: _skipAttestation,
        onStep: (step) {
          if (mounted) setState(() => _step = step);
        },
      );
      await services.session.completeReverification(result,
          key: attempt.newKey!, allowDeviceCredential: _allowDeviceCredential);
      if (mounted) setState(() => _result = result);
    });
  }

  @override
  Widget build(BuildContext context) {
    final services = AppScope.of(context);
    final start = _attempt?.start;
    final result = _result;
    return BankScaffold(
      title: 'Re-verify',
      body: ListView(
        padding: pagePadding(context),
        children: [
          if (result != null) ...[
            const CapabilityBanner(
              key: ValueKey('reverify-success'),
              kind: StatusKind.success,
              title: 'New approval key registered',
              message: 'The bank revoked the old key. Approvals are '
                  'unlocked.',
            ),
            gap,
            SectionCard(
              title: 'What the bank verified',
              child: ChecksView([...result.requestChecks, ...result.checks]),
            ),
            gap,
            FilledButton(
              key: const ValueKey('reverify-done'),
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Done'),
            ),
          ] else ...[
            CapabilityBanner(
              kind: StatusKind.warning,
              icon: Icons.lock_reset,
              title: 'Why re-verify?',
              message: '${widget.explanation} The silent device_binding key '
                  'is not tied to your biometrics (it has no user '
                  'authentication), so it still proves this is the bound '
                  'device. It cannot prove it is you — a one-time code does '
                  'that.',
            ),
            gap,
            SectionCard(
              title: '1 · Prove it\'s this device',
              subtitle: 'A request signed silently by device_binding',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Align(
                    alignment: Alignment.centerLeft,
                    child: OutlinedButton.icon(
                      key: const ValueKey('reverify-send-code'),
                      onPressed: _busy ? null : _sendCode,
                      icon: const Icon(Icons.sms_outlined),
                      label:
                          Text(start == null ? 'Send code' : 'Send a new code'),
                    ),
                  ),
                  if (start != null) ...[
                    const SizedBox(height: 8),
                    ChecksView(start.checks),
                  ],
                ],
              ),
            ),
            if (start != null) ...[
              gap,
              SectionCard(
                title: '2 · Prove it\'s you',
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    SimulatedSmsCard(
                      outbox: services.server.outbox,
                      subject: start.reverifyId,
                      onUseCode: (code) => _otp.text = code,
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      key: const ValueKey('reverify-otp-field'),
                      controller: _otp,
                      keyboardType: TextInputType.number,
                      maxLength: 6,
                      decoration: InputDecoration(
                        labelText: 'One-time code',
                        helperText: 'Sent to ${start.otpSentTo}',
                      ),
                    ),
                  ],
                ),
              ),
              gap,
              SectionCard(
                title: '3 · New approval key',
                subtitle: services.capabilities.supportsAttestation
                    ? 'Attested with a fresh challenge'
                    : 'Unattested on ${services.platform.label}',
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    SwitchListTile(
                      contentPadding: EdgeInsets.zero,
                      value: _allowDeviceCredential,
                      onChanged: _busy
                          ? null
                          : (v) => setState(() => _allowDeviceCredential = v),
                      title: const Text(
                          'Allow device PIN / passcode for approvals'),
                      subtitle: const Text('A PIN fallback caps approvals at '
                          'tier B.'),
                    ),
                    const SizedBox(height: 8),
                    FilledButton.icon(
                      key: const ValueKey('reverify-finish'),
                      onPressed: _busy || _otp.text.trim().length != 6
                          ? null
                          : _finish,
                      icon: const Icon(Icons.fingerprint),
                      label: const Text('Create new key & finish'),
                    ),
                  ],
                ),
              ),
            ],
            if (_busy) ...[gap, BusyStep(_step!)],
            if (_error != null) ...[gap, _errorView(_error!)],
          ],
        ],
      ),
    );
  }

  Widget _errorView(Object error) {
    if (error is KeySetupException) {
      if (error.attestationNotReady) {
        return ErrorBanner(
          guidance: guidanceFor(error.code),
          rawMessage: error.message,
          actionLabel: 'Continue without attestation (tier B max)',
          onAction: _busy
              ? null
              : () {
                  _skipAttestation = true;
                  _finish();
                },
        );
      }
      return ErrorBanner(
        guidance: guidanceFor(error.code),
        rawMessage: '${KeyAliases.approval}: ${error.message}',
        actionLabel: 'Try again',
        onAction: _busy ? null : _finish,
      );
    }
    if (error is BankError) {
      if (error.kind == BankErrorKind.signing) {
        return ErrorBanner(
            guidance: guidanceFor(error.code), rawMessage: error.message);
      }
      return SectionCard(
        title: 'The bank rejected the request',
        subtitle: error.message,
        child: ChecksView([...error.requestChecks, ...error.checks],
            emptyText: 'No details.'),
      );
    }
    return ErrorBanner(
        guidance: guidanceFor(BiometricError.unknown), rawMessage: '$error');
  }
}
