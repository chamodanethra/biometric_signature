import 'dart:convert';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secure_vault_example/client/reveal_service.dart';
import 'package:secure_vault_example/client/sharing.dart';
import 'package:secure_vault_example/models/sealed_item.dart';
import 'package:secure_vault_example/models/vault_key_record.dart';

import 'support/test_device.dart';

void main() {
  restorePluginPlatformAfterEachTest();

  for (final (recipientPlatform, recipientChoice, sender) in [
    (DevicePlatform.ios, VaultKeyChoice.ec, DevicePlatform.android),
    (DevicePlatform.ios, VaultKeyChoice.rsa, DevicePlatform.android),
    (DevicePlatform.android, VaultKeyChoice.ec, DevicePlatform.ios),
    (DevicePlatform.android, VaultKeyChoice.rsa, DevicePlatform.macos),
  ]) {
    test(
        '${sender.label} seals for a ${recipientPlatform.label} '
        '${recipientChoice.name} vault', () async {
      final alice = await TestDevice.start(sender);
      await alice.provision(VaultKeyChoice.ec);
      final bob = await TestDevice.start(recipientPlatform);
      await bob.provision(recipientChoice);

      // Bob exports his address (getKeyInfo with KeyFormat.pem).
      bob.use();
      final addressJson = (await bob.controller.myAddress()).encode();
      final getKeyInfo =
          bob.fake.calls.lastWhere((c) => c.method == 'getKeyInfo');
      expect(getKeyInfo.arguments['keyFormat'], KeyFormat.pem);
      expect(addressJson, contains('-----BEGIN PUBLIC KEY-----'));

      // Alice re-derives Bob's scheme from his platform and key.
      alice.use();
      final address = VaultAddress.parse(addressJson);
      expect(address.platform, recipientPlatform);
      expect(
          address.fingerprint, bob.controller.record!.encryptionKeyFingerprint);
      expect(address.scheme.label, bob.controller.record!.scheme.label);

      final aliceCalls = alice.fake.calls.length;
      final short = sealForRecipient(address,
          title: 'Door code',
          secret: '2468',
          from: alice.controller.senderLabel);
      final longSecret =
          List.filled(30, 'line of a long shared secret').join('\n');
      final long = sealForRecipient(address,
          title: 'Runbook', secret: longSecret, from: 'Alice');
      // Sealing for someone else needs no key and no prompt.
      expect(alice.fake.calls.length, aliceCalls);

      // Alice cannot import it: it is not sealed to her key.
      await expectLater(
        alice.controller.importShared(short),
        throwsA(isA<SharingException>().having(
            (e) => e.message, 'message', contains('not to this vault'))),
      );

      bob.use();
      final a = await bob.controller.importShared(short);
      final b = await bob.controller.importShared(long);
      expect(a.origin, ItemOrigin.shared);
      expect(a.format, SealFormat.direct);
      expect(b.format, SealFormat.envelope);
      expect(bob.services.repository.byId(a.id), isNotNull);

      final ra = await bob.controller.reveal(a);
      final rb = await bob.controller.reveal(b);
      expect((ra as Revealed).plaintext, '2468');
      expect((rb as Revealed).plaintext, longSecret);
    });
  }

  group('VaultAddress.parse rejects', () {
    late String addressJson;

    setUp(() async {
      final bob = await TestDevice.start(DevicePlatform.ios);
      await bob.provision(VaultKeyChoice.ec);
      addressJson = (await bob.controller.myAddress()).encode();
    });

    Map<String, dynamic> edit() =>
        (jsonDecode(addressJson) as Map).cast<String, dynamic>();

    test('an address whose scheme does not match its platform and key', () {
      final json = edit();
      (json['scheme'] as Map)['variant'] = 'android';
      expect(() => VaultAddress.parse(jsonEncode(json)),
          throwsA(isA<SharingException>()));
    });

    test('a platform that cannot receive (Windows)', () {
      final json = edit()..['platform'] = 'windows';
      expect(
        () => VaultAddress.parse(jsonEncode(json)),
        throwsA(isA<SharingException>()
            .having((e) => e.message, 'message', contains('notAvailable'))),
      );
    });

    test('an Android EC key that is not in hybrid mode', () {
      final json = edit()..['platform'] = 'android';
      expect(
        () => VaultAddress.parse(jsonEncode(json)),
        throwsA(isA<SharingException>()
            .having((e) => e.message, 'message', contains('signing-only'))),
      );
    });

    test('something that is not an address', () {
      expect(() => VaultAddress.parse('{"type":"other"}'),
          throwsA(isA<SharingException>()));
      expect(() => VaultAddress.parse('not json'),
          throwsA(isA<SharingException>()));
    });
  });

  test('a sender on Windows can still seal for others', () async {
    final bob = await TestDevice.start(DevicePlatform.android);
    await bob.provision(VaultKeyChoice.rsa);
    final addressJson = (await bob.controller.myAddress()).encode();

    final windows = await TestDevice.start(DevicePlatform.windows);
    final sealed = sealForRecipient(VaultAddress.parse(addressJson),
        title: 'Hello',
        secret: 'from a PC',
        from: windows.controller.senderLabel);
    expect(windows.fake.calls.where((c) => c.method == 'decrypt'), isEmpty);

    bob.use();
    final item = await bob.controller.importShared(sealed);
    final revealed = await bob.controller.reveal(item) as Revealed;
    expect(revealed.plaintext, 'from a PC');
    expect(item.from, contains('Windows'));
  });
}
