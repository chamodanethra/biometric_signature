import 'dart:convert';
import 'package:banking_app_example/models/account.dart';
import 'package:banking_app_example/models/transaction.dart';
import 'package:banking_app_example/services/biometric_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

class TransactionService {
  final BiometricService _biometricService = BiometricService();
  static const String _transactionsKey = 'transactions';
  static const String _accountsKey = 'accounts';

  /// Get all accounts
  Future<List<Account>> getAccounts() async {
    final prefs = await SharedPreferences.getInstance();
    final accountsJson = prefs.getString(_accountsKey);

    if (accountsJson != null) {
      final List<dynamic> decoded = jsonDecode(accountsJson);
      return decoded.map((json) => _accountFromJson(json)).toList();
    }

    // Return default accounts if none exist
    return _getDefaultAccounts();
  }

  /// Save accounts
  Future<void> _saveAccounts(List<Account> accounts) async {
    final prefs = await SharedPreferences.getInstance();
    final accountsJson = jsonEncode(
      accounts.map((a) => _accountToJson(a)).toList(),
    );
    await prefs.setString(_accountsKey, accountsJson);
  }

  /// Get transaction history
  Future<List<Transaction>> getTransactions() async {
    final prefs = await SharedPreferences.getInstance();
    final transactionsJson = prefs.getString(_transactionsKey);

    if (transactionsJson != null) {
      final List<dynamic> decoded = jsonDecode(transactionsJson);
      return decoded.map((json) => _transactionFromJson(json)).toList();
    }

    return [];
  }

  /// Create and sign a transaction
  Future<Transaction> createTransaction({
    required String fromAccountId,
    required String toAccountId,
    required double amount,
    String? description,
  }) async {
    // Validate accounts and balance
    final accounts = await getAccounts();
    final fromAccount = accounts.firstWhere((a) => a.id == fromAccountId);

    if (fromAccount.balance < amount) {
      throw Exception('Insufficient balance');
    }

    // Create transaction
    final transaction = Transaction(
      id: DateTime.now().millisecondsSinceEpoch.toString(),
      fromAccount: fromAccountId,
      toAccount: toAccountId,
      amount: amount,
      timestamp: DateTime.now(),
      signature: '', // Will be filled after signing
      status: TransactionStatus.pending,
      description: description,
    );

    // Sign transaction with biometric
    final signature = await _biometricService.signData(
      transaction.toSignaturePayload(),
      'Authorize transfer of \$${amount.toStringAsFixed(2)}',
    );

    // Create signed transaction
    final signedTransaction = Transaction(
      id: transaction.id,
      fromAccount: transaction.fromAccount,
      toAccount: transaction.toAccount,
      amount: transaction.amount,
      timestamp: transaction.timestamp,
      signature: signature,
      status: TransactionStatus.pending,
      description: transaction.description,
    );

    // Verify and process transaction
    final isValid = await _verifyTransaction(signedTransaction);

    if (isValid) {
      await _processTransaction(signedTransaction);
      return Transaction(
        id: signedTransaction.id,
        fromAccount: signedTransaction.fromAccount,
        toAccount: signedTransaction.toAccount,
        amount: signedTransaction.amount,
        timestamp: signedTransaction.timestamp,
        signature: signedTransaction.signature,
        status: TransactionStatus.completed,
        description: signedTransaction.description,
      );
    } else {
      throw Exception('Transaction verification failed');
    }
  }

  /// Verify transaction signature (simulated server-side verification)
  Future<bool> _verifyTransaction(Transaction transaction) async {
    // In a real app, this would be done on the server
    // The server would:
    // 1. Retrieve the user's public key
    // 2. Verify the signature against the transaction payload
    // 3. Check transaction validity (balance, limits, etc.)

    // For this example, we simulate a successful verification
    await Future.delayed(const Duration(milliseconds: 500));

    // Verify signature is not empty
    if (transaction.signature.isEmpty) {
      return false;
    }

    return true;
  }

  /// Process transaction (update balances and save)
  Future<void> _processTransaction(Transaction transaction) async {
    final accounts = await getAccounts();

    // Update balances
    final updatedAccounts = accounts.map((account) {
      if (account.id == transaction.fromAccount) {
        return account.copyWith(balance: account.balance - transaction.amount);
      } else if (account.id == transaction.toAccount) {
        return account.copyWith(balance: account.balance + transaction.amount);
      }
      return account;
    }).toList();

    // Save updated accounts
    await _saveAccounts(updatedAccounts);

    // Save transaction to history
    await _saveTransaction(transaction);
  }

  /// Save transaction to history
  Future<void> _saveTransaction(Transaction transaction) async {
    final prefs = await SharedPreferences.getInstance();
    final transactions = await getTransactions();
    transactions.insert(0, transaction); // Add to beginning

    final transactionsJson = jsonEncode(
      transactions.map((t) => _transactionToJson(t)).toList(),
    );
    await prefs.setString(_transactionsKey, transactionsJson);
  }

  /// Reset demo data
  Future<void> resetData() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_transactionsKey);
    await prefs.remove(_accountsKey);
  }

  // Helper methods for JSON serialization
  Map<String, dynamic> _accountToJson(Account account) {
    return {
      'id': account.id,
      'name': account.name,
      'balance': account.balance,
      'accountNumber': account.accountNumber,
      'currency': account.currency,
    };
  }

  Account _accountFromJson(Map<String, dynamic> json) {
    return Account(
      id: json['id'],
      name: json['name'],
      balance: json['balance'],
      accountNumber: json['accountNumber'],
      currency: json['currency'] ?? 'USD',
    );
  }

  Map<String, dynamic> _transactionToJson(Transaction transaction) {
    return {
      'id': transaction.id,
      'fromAccount': transaction.fromAccount,
      'toAccount': transaction.toAccount,
      'amount': transaction.amount,
      'timestamp': transaction.timestamp.toIso8601String(),
      'signature': transaction.signature,
      'status': transaction.status.index,
      'description': transaction.description,
    };
  }

  Transaction _transactionFromJson(Map<String, dynamic> json) {
    return Transaction(
      id: json['id'],
      fromAccount: json['fromAccount'],
      toAccount: json['toAccount'],
      amount: json['amount'],
      timestamp: DateTime.parse(json['timestamp']),
      signature: json['signature'],
      status: TransactionStatus.values[json['status']],
      description: json['description'],
    );
  }

  List<Account> _getDefaultAccounts() {
    return [
      Account(
        id: 'checking',
        name: 'Checking Account',
        balance: 5420.50,
        accountNumber: '****1234',
      ),
      Account(
        id: 'savings',
        name: 'Savings Account',
        balance: 12350.75,
        accountNumber: '****5678',
      ),
    ];
  }
}
