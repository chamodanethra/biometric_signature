import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/attestation.dart';
import 'package:examples_shared/server.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/attestation_fixtures.dart';

void main() {
  Widget host(Widget child, {Brightness brightness = Brightness.light}) =>
      MaterialApp(
        theme: buildExampleTheme(
            seed: Colors.indigo, brightness: Brightness.light),
        darkTheme:
            buildExampleTheme(seed: Colors.indigo, brightness: Brightness.dark),
        themeMode:
            brightness == Brightness.dark ? ThemeMode.dark : ThemeMode.light,
        home: Scaffold(body: child),
      );

  testWidgets('theme carries StatusColors for both brightnesses',
      (tester) async {
    late StatusColors light;
    await tester.pumpWidget(host(Builder(builder: (context) {
      light = context.statusColors;
      return const SizedBox();
    })));
    expect(light.success, StatusColors.light.success);
    late StatusColors dark;
    await tester.pumpWidget(host(Builder(builder: (context) {
      dark = context.statusColors;
      return const SizedBox();
    }), brightness: Brightness.dark));
    await tester.pumpAndSettle();
    expect(dark.success, StatusColors.dark.success);
    expect(StatusColors.light.lerp(StatusColors.dark, 1).danger,
        StatusColors.dark.danger);
  });

  for (final size in [const Size(360, 800), const Size(1024, 800)]) {
    testWidgets('AttestationReportView renders at ${size.width}px',
        (tester) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      final f = AttestationFixture('caiman/sdk36/SB_EC_RKP');
      final report = AttestationVerifier(now: () => f.validAt).verify(
        chain: f.chain,
        expectedChallenge: f.challenge,
        expectedPublicKey: f.leafPublicKey,
      );
      await tester.pumpWidget(host(SingleChildScrollView(
        child: AttestationReportView(report: report),
      )));
      expect(find.text('StrongBox'), findsWidgets);
      expect(find.text('Challenge matches'), findsOneWidget);
      expect(find.text('Revocation not checked'), findsOneWidget);
      expect(find.text('Copy chain as PEM'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('copy buttons write to the clipboard', (tester) async {
    String? copied;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = (call.arguments as Map)['text'] as String?;
        }
        return null;
      },
    );
    await tester.pumpWidget(host(const Column(children: [
      KeyValueRow(label: 'Public key', value: 'MFkw', monospace: true),
      MonoBlock(label: 'Signature', text: 'abcd'),
    ])));
    await tester.tap(find.byTooltip('Copy Public key'));
    await tester.pump();
    expect(copied, 'MFkw');
    await tester.tap(find.byTooltip('Copy Signature'));
    await tester.pump();
    expect(copied, 'abcd');
    expect(find.text('Signature copied'), findsOneWidget);
  });

  testWidgets('ErrorBanner shows guidance and runs the action', (tester) async {
    var tapped = false;
    await tester.pumpWidget(host(ErrorBanner(
      guidance: guidanceFor(BiometricError.keyInvalidated),
      rawMessage: 'KeyPermanentlyInvalidatedException',
      onAction: () => tapped = true,
    )));
    expect(find.textContaining('Key invalidated'), findsOneWidget);
    await tester.tap(find.text('Register again'));
    expect(tapped, isTrue);
  });

  testWidgets('misc widgets render', (tester) async {
    await tester.pumpWidget(host(ListView(children: [
      const SectionCard(
        title: 'Device',
        subtitle: 'Capabilities',
        trailing: StatusChip(label: 'TEE', kind: StatusKind.success),
        child: CapabilityBanner(
          title: 'Windows',
          message: 'decrypt() returns notAvailable',
          kind: StatusKind.warning,
        ),
      ),
      StatusChip.forCheck(CheckStatus.fail),
      const CheckRow(kind: StatusKind.info, title: 'Info', detail: 'Detail'),
    ])));
    expect(find.text('FAIL'), findsOneWidget);
    expect(find.text('Device'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('DevConsoleScaffold opens a tabbed sheet with live logs',
      (tester) async {
    final transport = MockTransport(latency: Duration.zero)
      ..register('/ping', (body) async => {'ok': true});
    final audit = AuditLog();
    await tester.pumpWidget(MaterialApp(
      theme: buildExampleTheme(seed: Colors.teal, brightness: Brightness.light),
      home: DevConsoleScaffold(
        title: const Text('Demo'),
        body: const Text('Body'),
        consoleTabs: [
          DevConsoleTab(
            label: 'Wire',
            icon: Icons.swap_vert,
            builder: (_) => WireLogView(log: transport.log),
          ),
          DevConsoleTab(
            label: 'Audit',
            builder: (_) => AuditLogView(log: audit),
          ),
        ],
      ),
    ));
    await tester.tap(find.byTooltip('Server console'));
    await tester.pumpAndSettle();
    expect(find.text('No requests yet.'), findsOneWidget);

    await tester.runAsync(() => transport.call('/ping', {'n': 1}));
    await tester.pumpAndSettle();
    expect(find.text('/ping'), findsOneWidget);
    expect(find.text('OK'), findsOneWidget);
    await tester.tap(find.text('/ping'));
    await tester.pumpAndSettle();
    expect(find.text('Request'), findsOneWidget);

    await tester.tap(find.text('Audit'));
    await tester.pumpAndSettle();
    await tester.runAsync(() => audit.record('server', 'login.rejected',
        detail: 'replay', severity: AuditSeverity.danger));
    await tester.pumpAndSettle();
    expect(find.text('login.rejected'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
