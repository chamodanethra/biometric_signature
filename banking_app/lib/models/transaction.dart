class Transaction {
  final String id;
  final String fromAccount;
  final String toAccount;
  final double amount;
  final DateTime timestamp;
  final String signature;
  final TransactionStatus status;
  final String? description;

  Transaction({
    required this.id,
    required this.fromAccount,
    required this.toAccount,
    required this.amount,
    required this.timestamp,
    required this.signature,
    required this.status,
    this.description,
  });

  Map<String, dynamic> toPayload() {
    return {
      'id': id,
      'from': fromAccount,
      'to': toAccount,
      'amount': amount.toStringAsFixed(2),
      'timestamp': timestamp.toIso8601String(),
      'description': description ?? '',
    };
  }

  String toSignaturePayload() {
    // Create a deterministic string for signing
    return '${toPayload()['id']}|${toPayload()['from']}|${toPayload()['to']}|${toPayload()['amount']}|${toPayload()['timestamp']}';
  }
}

enum TransactionStatus {
  pending,
  completed,
  failed,
  cancelled,
}

extension TransactionStatusExtension on TransactionStatus {
  String get displayName {
    switch (this) {
      case TransactionStatus.pending:
        return 'Pending';
      case TransactionStatus.completed:
        return 'Completed';
      case TransactionStatus.failed:
        return 'Failed';
      case TransactionStatus.cancelled:
        return 'Cancelled';
    }
  }
}
