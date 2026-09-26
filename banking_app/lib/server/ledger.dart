/// Accounts, payees and postings of the mock bank.
library;

import 'package:examples_shared/crypto.dart';
import 'package:examples_shared/server.dart';

import 'models.dart';

/// The demo customer. A real bank would identify the customer with a
/// password, a one-time code or an identity check before binding a device.
abstract final class DemoCustomer {
  /// Customer id.
  static const String id = 'cust-alex';

  /// Display name.
  static const String name = 'Alex Morgan';

  /// Where the simulated SMS codes "go".
  static const String phone = '+1 ••• ••• 0142';
}

/// The bank's books, persisted in a [KeyValueStore].
class Ledger with Observable {
  /// Creates a ledger. Call [load] before use.
  Ledger({required this.store, required this.clock});

  /// Persistence.
  final KeyValueStore store;

  /// The bank's clock.
  final Clock clock;

  /// Saved payees (fixed for the demo).
  static const List<Payee> payees = [
    Payee(id: 'p-alice', name: 'Alice Chen', account: '••3310'),
    Payee(id: 'p-bob', name: "Bob's Hardware", account: '••9082'),
    Payee(id: 'p-rent', name: 'Harbor Lofts (rent)', account: '••5521'),
  ];

  static const List<Account> _seedAccounts = [
    Account(
        id: 'CHK-4821',
        name: 'Everyday Checking',
        customerId: DemoCustomer.id,
        balanceCents: 525000),
    Account(
        id: 'SAV-7730',
        name: 'Savings',
        customerId: DemoCustomer.id,
        balanceCents: 1280000),
  ];

  final List<Account> _accounts = [];
  final List<Posting> _postings = [];

  /// Every account.
  List<Account> get accounts => List.unmodifiable(_accounts);

  /// Every posting, oldest first.
  List<Posting> get postings => List.unmodifiable(_postings);

  /// Loads persisted books, seeding them on first run.
  Future<void> load() async {
    final accounts = await store.readList('accounts');
    final postings = await store.readList('postings');
    if (accounts == null) {
      await reseed();
      return;
    }
    _accounts
      ..clear()
      ..addAll([
        for (final a in accounts) Account.fromJson(a as Map<String, dynamic>)
      ]);
    _postings
      ..clear()
      ..addAll([
        for (final p in postings ?? const <dynamic>[])
          Posting.fromJson(p as Map<String, dynamic>)
      ]);
    notifyListeners();
  }

  /// Restores the demo balances and a little history.
  Future<void> reseed() async {
    final now = clock.now();
    _accounts
      ..clear()
      ..addAll(_seedAccounts);
    _postings
      ..clear()
      ..addAll([
        Posting(
          id: 'seed-1',
          time: now.subtract(const Duration(days: 3)),
          accountId: 'CHK-4821',
          amountCents: 480000,
          description: 'Salary — Northwind Ltd',
          balanceAfterCents: 541250,
        ),
        Posting(
          id: 'seed-2',
          time: now.subtract(const Duration(days: 2)),
          accountId: 'CHK-4821',
          amountCents: -6250,
          description: 'Card — Green Grocer',
          balanceAfterCents: 535000,
        ),
        Posting(
          id: 'seed-3',
          time: now.subtract(const Duration(days: 1)),
          accountId: 'CHK-4821',
          amountCents: -10000,
          description: 'Card — City Transit',
          balanceAfterCents: 525000,
        ),
      ]);
    await _persist();
  }

  /// Accounts of [customerId].
  List<Account> accountsFor(String customerId) => [
        for (final a in _accounts)
          if (a.customerId == customerId) a
      ];

  /// The account [id], if any.
  Account? account(String id) {
    for (final a in _accounts) {
      if (a.id == id) return a;
    }
    return null;
  }

  /// The payee [id], if any.
  Payee? payee(String id) {
    for (final p in payees) {
      if (p.id == id) return p;
    }
    return null;
  }

  /// Newest postings on [customerId]'s accounts.
  List<Posting> recentFor(String customerId, {int limit = 15}) {
    final ids = {for (final a in accountsFor(customerId)) a.id};
    return _postings.reversed
        .where((p) => ids.contains(p.accountId))
        .take(limit)
        .toList();
  }

  /// Debits [amountCents] from [accountId]. Throws [StateError] if the
  /// account is unknown or the balance is insufficient.
  Future<Posting> debit({
    required String accountId,
    required int amountCents,
    required String description,
    String? txnId,
    RiskTier? tier,
  }) async {
    final index = _accounts.indexWhere((a) => a.id == accountId);
    if (index < 0) throw StateError('Unknown account $accountId');
    final account = _accounts[index];
    if (account.balanceCents < amountCents) {
      throw StateError('Insufficient funds');
    }
    final updated = account.withBalance(account.balanceCents - amountCents);
    _accounts[index] = updated;
    final posting = Posting(
      id: 'pst-${toHex(secureRandomBytes(4))}',
      time: clock.now(),
      accountId: accountId,
      amountCents: -amountCents,
      description: description,
      balanceAfterCents: updated.balanceCents,
      txnId: txnId,
      tier: tier,
    );
    _postings.add(posting);
    if (_postings.length > 200) _postings.removeAt(0);
    await _persist();
    return posting;
  }

  Future<void> _persist() async {
    await store.write('accounts', [for (final a in _accounts) a.toJson()]);
    await store.write('postings', [for (final p in _postings) p.toJson()]);
    notifyListeners();
  }
}
