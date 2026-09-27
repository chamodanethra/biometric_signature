import 'dart:convert';
import 'dart:typed_data';

import 'package:examples_shared/server.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late MockTransport transport;
  late List<Map<String, dynamic>> received;

  setUp(() {
    received = [];
    transport = MockTransport(latency: Duration.zero);
    transport.register('/echo', (body) async {
      received.add(body);
      return {'ok': true, 'echo': body};
    });
  });

  test('JSON round trip in both directions', () async {
    final response = await transport.call('/echo', {
      'n': 1,
      'nested': {
        'list': [1, 'a', null]
      },
    });
    expect(response['echo'], {
      'n': 1,
      'nested': {
        'list': [1, 'a', null]
      },
    });
    expect(transport.log.entries.single.response, response);
    expect(transport.log.entries.single.elapsed, isNotNull);
  });

  test('bytes must be sent as base64 strings', () async {
    // A Uint8List becomes a plain JSON array, not bytes.
    await transport.call('/echo', {
      'raw': Uint8List.fromList([1, 2])
    });
    expect(received.single['raw'], isNot(isA<Uint8List>()));
    expect(() => transport.call('/echo', {'bad': DateTime(2020)}),
        throwsA(isA<JsonUnsupportedObjectError>()));
  });

  test('failNext fails once, before the server sees the request', () async {
    transport.failNext('/echo');
    expect(transport.pendingFaults, hasLength(1));
    await expectLater(
      transport.call('/echo', {'a': 1}),
      throwsA(isA<TransportException>()
          .having((e) => e.kind, 'kind', TransportErrorKind.injected)),
    );
    expect(received, isEmpty);
    expect(transport.log.entries.single.failed, isTrue);
    expect(transport.pendingFaults, isEmpty);
    await transport.call('/echo', {'a': 1});
    expect(received, hasLength(1));
  });

  test('tamper modifies the request after the client built it', () async {
    transport.tamper('/echo', 'payload.amount', Tamper.add(100000));
    await transport.call('/echo', {
      'payload': {'amount': 125},
      'signature': 'sig',
    });
    expect((received.single['payload'] as Map)['amount'], 100125);
    expect(transport.log.entries.single.faults.single,
        contains('tamper payload.amount'));
    // Only once.
    await transport.call('/echo', {
      'payload': {'amount': 125},
    });
    expect((received.last['payload'] as Map)['amount'], 125);
  });

  test('tamper helpers and missing fields', () async {
    final sig = base64.encode([0, 1, 2]);
    transport.tamper('/e*', 'signature', Tamper.flipBase64Bit);
    await transport.call('/echo', {'signature': sig});
    expect(base64.decode(received.single['signature'] as String), [1, 1, 2]);
    transport.tamper('/echo', 'items.1', Tamper.replaceWith('x'));
    await transport.call('/echo', {
      'items': ['a', 'b'],
    });
    expect(received.last['items'], ['a', 'x']);
    transport.tamper('/echo', 'missing.field', Tamper.replaceWith(1));
    await transport.call('/echo', {'a': 1});
    expect(transport.log.entries.last.faults.single, contains('not found'));
  });

  test('replayLast resends exactly what the server received', () async {
    expect(transport.canReplay('/echo'), isFalse);
    expect(() => transport.replayLast('/echo'), throwsStateError);
    await transport.call('/echo', {'nonce': 'abc'});
    final replayed = await transport.replayLast('/echo');
    expect(replayed['echo'], {'nonce': 'abc'});
    expect(received, hasLength(2));
    expect(received[0], received[1]);
    expect(transport.log.entries.last.faults, ['replay']);
  });

  test('unknown routes and handler errors become TransportExceptions',
      () async {
    await expectLater(
        transport.call('/nope', {}),
        throwsA(isA<TransportException>()
            .having((e) => e.kind, 'kind', TransportErrorKind.unknownRoute)));
    transport.register('/boom', (_) async => throw StateError('db down'));
    await expectLater(
        transport.call('/boom', {}),
        throwsA(isA<TransportException>()
            .having((e) => e.kind, 'kind', TransportErrorKind.serverError)));
    expect(transport.log.entries.last.error, contains('db down'));
  });

  test('the wire log notifies listeners and caps its size', () async {
    final log = WireLog(maxEntries: 2);
    final t = MockTransport(latency: Duration.zero, log: log)
      ..register('/x', (b) async => {'ok': true});
    var notifications = 0;
    void listener() => notifications++;
    log.addListener(listener);
    for (var i = 0; i < 3; i++) {
      await t.call('/x', {'i': i});
    }
    expect(log.entries, hasLength(2));
    expect(log.entries.first.request['i'], 1);
    expect(notifications, greaterThan(0));
    log.removeListener(listener);
    log.clear();
    expect(log.entries, isEmpty);
  });

  test('simulated latency', () async {
    final t = MockTransport(latency: const Duration(milliseconds: 20))
      ..register('/x', (b) async => {'ok': true});
    final sw = Stopwatch()..start();
    await t.call('/x', {});
    expect(sw.elapsedMilliseconds, greaterThanOrEqualTo(18));
  });
}
