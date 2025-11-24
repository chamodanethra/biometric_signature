import 'package:banking_app_example/models/account.dart';
import 'package:banking_app_example/models/transaction.dart';
import 'package:banking_app_example/services/transaction_service.dart';
import 'package:banking_app_example/widgets/transaction_tile.dart';
import 'package:flutter/material.dart';

class HistoryScreen extends StatefulWidget {
  final List<Account> accounts;

  const HistoryScreen({super.key, required this.accounts});

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  final TransactionService _transactionService = TransactionService();
  List<Transaction> _transactions = [];
  bool _isLoading = true;
  String? _selectedAccountId;

  @override
  void initState() {
    super.initState();
    _loadTransactions();
  }

  Future<void> _loadTransactions() async {
    setState(() => _isLoading = true);
    final transactions = await _transactionService.getTransactions();
    setState(() {
      _transactions = transactions;
      _isLoading = false;
    });
  }

  List<Transaction> get _filteredTransactions {
    if (_selectedAccountId == null) {
      return _transactions;
    }
    return _transactions
        .where(
          (t) =>
              t.fromAccount == _selectedAccountId ||
              t.toAccount == _selectedAccountId,
        )
        .toList();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Transaction History'),
        actions: [
          PopupMenuButton<String?>(
            icon: const Icon(Icons.filter_list),
            onSelected: (value) {
              setState(() => _selectedAccountId = value);
            },
            itemBuilder: (context) => [
              const PopupMenuItem(value: null, child: Text('All Accounts')),
              ...widget.accounts.map(
                (account) =>
                    PopupMenuItem(value: account.id, child: Text(account.name)),
              ),
            ],
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : _filteredTransactions.isEmpty
              ? Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.history, size: 64, color: Colors.grey[400]),
                      const SizedBox(height: 16),
                      Text(
                        'No transactions yet',
                        style: TextStyle(fontSize: 18, color: Colors.grey[600]),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Make your first transfer to see it here',
                        style: TextStyle(fontSize: 14, color: Colors.grey[500]),
                      ),
                    ],
                  ),
                )
              : RefreshIndicator(
                  onRefresh: _loadTransactions,
                  child: Column(
                    children: [
                      if (_selectedAccountId != null)
                        Container(
                          padding: const EdgeInsets.all(12),
                          color: Colors.blue.withOpacity(0.1),
                          child: Row(
                            children: [
                              const Icon(Icons.filter_list, size: 16),
                              const SizedBox(width: 8),
                              Text(
                                'Filtered by: ${widget.accounts.firstWhere((a) => a.id == _selectedAccountId).name}',
                                style: const TextStyle(fontSize: 14),
                              ),
                              const Spacer(),
                              TextButton(
                                onPressed: () {
                                  setState(() => _selectedAccountId = null);
                                },
                                child: const Text('Clear'),
                              ),
                            ],
                          ),
                        ),
                      Expanded(
                        child: ListView.builder(
                          padding: const EdgeInsets.symmetric(vertical: 8),
                          itemCount: _filteredTransactions.length,
                          itemBuilder: (context, index) {
                            final transaction = _filteredTransactions[index];
                            return TransactionTile(
                              transaction: transaction,
                              currentAccountId: _selectedAccountId ?? 'all',
                            );
                          },
                        ),
                      ),
                    ],
                  ),
                ),
    );
  }
}
