import 'package:flutter/material.dart';
import 'package:banking_app_example/models/account.dart';
import 'package:banking_app_example/services/biometric_service.dart';
import 'package:banking_app_example/services/transaction_service.dart';
import 'package:banking_app_example/widgets/account_card.dart';
import 'package:banking_app_example/screens/transfer_screen.dart';
import 'package:banking_app_example/screens/history_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final BiometricService _biometricService = BiometricService();
  final TransactionService _transactionService = TransactionService();

  List<Account> _accounts = [];
  bool _isLoading = true;
  bool _isInitialized = false;
  String? _biometricType;

  @override
  void initState() {
    super.initState();
    _initialize();
  }

  Future<void> _initialize() async {
    setState(() => _isLoading = true);

    try {
      // Check biometric availability
      final availability = await _biometricService.checkAvailability();

      if (!availability.isAvailable) {
        _showError('Biometric authentication is not available on this device');
        return;
      }

      setState(() => _biometricType = availability.displayName);

      // Check if keys exist
      final hasKeys = await _biometricService.hasKeys();

      if (!hasKeys) {
        await _setupBiometrics();
      }

      // Load accounts
      await _loadAccounts();

      setState(() {
        _isInitialized = true;
        _isLoading = false;
      });
    } catch (e) {
      _showError('Initialization failed: $e');
      setState(() => _isLoading = false);
    }
  }

  Future<void> _setupBiometrics() async {
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: const Text('Setup Biometric Authentication'),
        content: const Text(
          'This app uses biometric authentication to securely sign transactions. '
          'Your biometric data never leaves your device.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Setup'),
          ),
        ],
      ),
    );

    if (confirmed != true) {
      if (mounted) {
        Navigator.of(context).pop();
      }
      return;
    }

    try {
      await _biometricService.initializeKeys();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Biometric authentication setup successful!'),
            backgroundColor: Colors.green,
          ),
        );
      }
    } catch (e) {
      _showError('Setup failed: $e');
      if (mounted) {
        Navigator.of(context).pop();
      }
    }
  }

  Future<void> _loadAccounts() async {
    final accounts = await _transactionService.getAccounts();
    setState(() => _accounts = accounts);
  }

  void _showError(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Colors.red,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Secure Banking'),
        actions: [
          if (_biometricType != null)
            Padding(
              padding: const EdgeInsets.only(right: 16),
              child: Center(
                child: Row(
                  children: [
                    Icon(
                      _biometricType!.contains('Face')
                          ? Icons.face
                          : Icons.fingerprint,
                      size: 20,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      _biometricType!,
                      style: const TextStyle(fontSize: 14),
                    ),
                  ],
                ),
              ),
            ),
          PopupMenuButton<String>(
            onSelected: (value) async {
              if (value == 'reset') {
                await _resetDemo();
              } else if (value == 'history') {
                _navigateToHistory();
              }
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'history',
                child: Row(
                  children: [
                    Icon(Icons.history),
                    SizedBox(width: 8),
                    Text('Transaction History'),
                  ],
                ),
              ),
              const PopupMenuItem(
                value: 'reset',
                child: Row(
                  children: [
                    Icon(Icons.refresh),
                    SizedBox(width: 8),
                    Text('Reset Demo'),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : !_isInitialized
              ? const Center(
                  child: Text('Biometric authentication not available'))
              : RefreshIndicator(
                  onRefresh: _loadAccounts,
                  child: ListView(
                    padding: const EdgeInsets.all(16),
                    children: [
                      const Text(
                        'My Accounts',
                        style: TextStyle(
                          fontSize: 24,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 16),
                      ..._accounts.map((account) => Padding(
                            padding: const EdgeInsets.only(bottom: 16),
                            child: AccountCard(account: account),
                          )),
                      const SizedBox(height: 16),
                      Card(
                        child: Padding(
                          padding: const EdgeInsets.all(16),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Row(
                                children: [
                                  Icon(Icons.security, color: Colors.green),
                                  SizedBox(width: 8),
                                  Text(
                                    'Secured by Biometrics',
                                    style: TextStyle(
                                      fontSize: 16,
                                      fontWeight: FontWeight.w500,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 8),
                              Text(
                                'All transactions are cryptographically signed using your device\'s secure hardware. '
                                'Your private key never leaves your device.',
                                style: TextStyle(
                                  fontSize: 13,
                                  color: Colors.grey[600],
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
      floatingActionButton: _isInitialized
          ? FloatingActionButton.extended(
              onPressed: _navigateToTransfer,
              icon: const Icon(Icons.send),
              label: const Text('Transfer'),
            )
          : null,
    );
  }

  void _navigateToTransfer() async {
    final result = await Navigator.push<bool>(
      context,
      MaterialPageRoute(
        builder: (context) => TransferScreen(accounts: _accounts),
      ),
    );

    if (result == true) {
      await _loadAccounts();
    }
  }

  void _navigateToHistory() {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => HistoryScreen(accounts: _accounts),
      ),
    );
  }

  Future<void> _resetDemo() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Reset Demo'),
        content: const Text(
          'This will reset all accounts and transactions to default values. '
          'Biometric keys will remain intact.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('Reset'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await _transactionService.resetData();
      await _loadAccounts();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Demo data reset successfully')),
        );
      }
    }
  }
}
