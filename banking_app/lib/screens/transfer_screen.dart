import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:banking_app_example/models/account.dart';
import 'package:banking_app_example/services/transaction_service.dart';
import 'package:intl/intl.dart';

class TransferScreen extends StatefulWidget {
  final List<Account> accounts;

  const TransferScreen({super.key, required this.accounts});

  @override
  State<TransferScreen> createState() => _TransferScreenState();
}

class _TransferScreenState extends State<TransferScreen> {
  final TransactionService _transactionService = TransactionService();
  final _formKey = GlobalKey<FormState>();
  final _amountController = TextEditingController();
  final _descriptionController = TextEditingController();

  Account? _fromAccount;
  Account? _toAccount;
  bool _isProcessing = false;

  @override
  void initState() {
    super.initState();
    if (widget.accounts.isNotEmpty) {
      _fromAccount = widget.accounts.first;
    }
  }

  @override
  void dispose() {
    _amountController.dispose();
    _descriptionController.dispose();
    super.dispose();
  }

  Future<void> _processTransfer() async {
    if (!_formKey.currentState!.validate()) return;

    if (_fromAccount == null || _toAccount == null) {
      _showError('Please select both accounts');
      return;
    }

    if (_fromAccount!.id == _toAccount!.id) {
      _showError('Cannot transfer to the same account');
      return;
    }

    final amount = double.tryParse(_amountController.text);
    if (amount == null || amount <= 0) {
      _showError('Invalid amount');
      return;
    }

    setState(() => _isProcessing = true);

    try {
      // Show confirmation dialog
      final confirmed = await _showConfirmationDialog(amount);

      if (!confirmed) {
        setState(() => _isProcessing = false);
        return;
      }

      // Create and sign transaction (this triggers biometric prompt)
      final transaction = await _transactionService.createTransaction(
        fromAccountId: _fromAccount!.id,
        toAccountId: _toAccount!.id,
        amount: amount,
        description: _descriptionController.text.trim(),
      );

      if (mounted) {
        // Show success
        await showDialog(
          context: context,
          barrierDismissible: false,
          builder: (context) => AlertDialog(
            title: const Row(
              children: [
                Icon(Icons.check_circle, color: Colors.green, size: 32),
                SizedBox(width: 12),
                Text('Transfer Successful'),
              ],
            ),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Amount: ${NumberFormat.currency(symbol: '\$').format(amount)}',
                ),
                Text('From: ${_fromAccount!.name}'),
                Text('To: ${_toAccount!.name}'),
                const SizedBox(height: 8),
                const Divider(),
                const SizedBox(height: 8),
                const Text(
                  'Transaction ID:',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                Text(
                  transaction.id,
                  style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
                ),
                const SizedBox(height: 8),
                const Text(
                  'Signature:',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                Text(
                  '${transaction.signature.substring(0, 32)}...',
                  style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
                ),
              ],
            ),
            actions: [
              ElevatedButton(
                onPressed: () {
                  Navigator.pop(context); // Close dialog
                  Navigator.pop(context, true); // Return to home with success
                },
                child: const Text('Done'),
              ),
            ],
          ),
        );
      }
    } catch (e) {
      _showError(e.toString());
      setState(() => _isProcessing = false);
    }
  }

  Future<bool> _showConfirmationDialog(double amount) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Confirm Transfer'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'You are about to transfer:',
              style: TextStyle(color: Colors.grey[600]),
            ),
            const SizedBox(height: 16),
            Text(
              NumberFormat.currency(symbol: '\$').format(amount),
              style: const TextStyle(fontSize: 32, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 16),
            _buildInfoRow('From', _fromAccount!.name),
            _buildInfoRow('To', _toAccount!.name),
            if (_descriptionController.text.isNotEmpty)
              _buildInfoRow('Note', _descriptionController.text),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.blue.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Row(
                children: [
                  Icon(Icons.info_outline, size: 20, color: Colors.blue),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'You will be asked to authenticate with biometrics',
                      style: TextStyle(fontSize: 12),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Confirm'),
          ),
        ],
      ),
    );

    return result ?? false;
  }

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 60,
            child: Text('$label:', style: TextStyle(color: Colors.grey[600])),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontWeight: FontWeight.w500),
            ),
          ),
        ],
      ),
    );
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: Colors.red),
    );
  }

  @override
  Widget build(BuildContext context) {
    final availableToAccounts =
        widget.accounts.where((a) => a.id != _fromAccount?.id).toList();

    return Scaffold(
      appBar: AppBar(title: const Text('Transfer Money')),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // From Account
            const Text(
              'From Account',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 8),
            DropdownButtonFormField<Account>(
              value: _fromAccount,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.account_balance_wallet),
              ),
              items: widget.accounts.map((account) {
                return DropdownMenuItem(
                  value: account,
                  child: Text(
                    '${account.name} - ${NumberFormat.currency(symbol: '\$').format(account.balance)}',
                    style: const TextStyle(fontSize: 14),
                  ),
                );
              }).toList(),
              onChanged: (value) {
                setState(() {
                  _fromAccount = value;
                  // Reset to account if it's the same as from
                  if (_toAccount?.id == value?.id) {
                    _toAccount = null;
                  }
                });
              },
              validator: (value) =>
                  value == null ? 'Please select an account' : null,
            ),

            const SizedBox(height: 24),

            // To Account
            const Text(
              'To Account',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 8),
            DropdownButtonFormField<Account>(
              value: _toAccount,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.account_balance),
              ),
              items: availableToAccounts.map((account) {
                return DropdownMenuItem(
                  value: account,
                  child: Text(account.name),
                );
              }).toList(),
              onChanged: (value) {
                setState(() => _toAccount = value);
              },
              validator: (value) =>
                  value == null ? 'Please select an account' : null,
            ),

            const SizedBox(height: 24),

            // Amount
            const Text(
              'Amount',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 8),
            TextFormField(
              controller: _amountController,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.attach_money),
                hintText: '0.00',
              ),
              keyboardType: const TextInputType.numberWithOptions(
                decimal: true,
              ),
              inputFormatters: [
                FilteringTextInputFormatter.allow(RegExp(r'^\d+\.?\d{0,2}')),
              ],
              validator: (value) {
                if (value == null || value.isEmpty) {
                  return 'Please enter an amount';
                }
                final amount = double.tryParse(value);
                if (amount == null || amount <= 0) {
                  return 'Please enter a valid amount';
                }
                if (_fromAccount != null && amount > _fromAccount!.balance) {
                  return 'Insufficient balance';
                }
                return null;
              },
            ),

            const SizedBox(height: 24),

            // Description (optional)
            const Text(
              'Description (Optional)',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 8),
            TextFormField(
              controller: _descriptionController,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.note),
                hintText: 'Add a note...',
              ),
              maxLines: 2,
            ),

            const SizedBox(height: 32),

            // Submit Button
            ElevatedButton(
              onPressed: _isProcessing ? null : _processTransfer,
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
              ),
              child: _isProcessing
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.fingerprint),
                        SizedBox(width: 8),
                        Text(
                          'Authenticate & Transfer',
                          style: TextStyle(fontSize: 16),
                        ),
                      ],
                    ),
            ),

            const SizedBox(height: 16),

            // Security Info
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.green.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.green.withOpacity(0.3)),
              ),
              child: const Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.security, color: Colors.green, size: 20),
                  SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      'This transaction will be cryptographically signed using '
                      'your device\'s secure hardware. You will be asked to '
                      'authenticate with biometrics.',
                      style: TextStyle(fontSize: 12),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
