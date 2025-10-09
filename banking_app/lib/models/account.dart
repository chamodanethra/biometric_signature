class Account {
  final String id;
  final String name;
  final double balance;
  final String accountNumber;
  final String currency;

  Account({
    required this.id,
    required this.name,
    required this.balance,
    required this.accountNumber,
    this.currency = 'USD',
  });

  Account copyWith({
    String? id,
    String? name,
    double? balance,
    String? accountNumber,
    String? currency,
  }) {
    return Account(
      id: id ?? this.id,
      name: name ?? this.name,
      balance: balance ?? this.balance,
      accountNumber: accountNumber ?? this.accountNumber,
      currency: currency ?? this.currency,
    );
  }
}
