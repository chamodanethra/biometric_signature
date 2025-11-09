import 'package:flutter/material.dart';
import 'package:banking_app_example/models/transaction.dart';
import 'package:intl/intl.dart';

class TransactionTile extends StatelessWidget {
  final Transaction transaction;
  final String currentAccountId;

  const TransactionTile({
    super.key,
    required this.transaction,
    required this.currentAccountId,
  });

  @override
  Widget build(BuildContext context) {
    final isOutgoing = transaction.fromAccount == currentAccountId;
    final formatter = NumberFormat.currency(symbol: '\$');
    final dateFormatter = DateFormat('MMM dd, yyyy - HH:mm');

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: isOutgoing
              ? Colors.red.withOpacity(0.1)
              : Colors.green.withOpacity(0.1),
          child: Icon(
            isOutgoing ? Icons.arrow_upward : Icons.arrow_downward,
            color: isOutgoing ? Colors.red : Colors.green,
          ),
        ),
        title: Text(
          isOutgoing
              ? 'Transfer to ${transaction.toAccount}'
              : 'Transfer from ${transaction.fromAccount}',
          style: const TextStyle(fontWeight: FontWeight.w500),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(dateFormatter.format(transaction.timestamp)),
            if (transaction.description?.isNotEmpty ?? false)
              Text(
                transaction.description!,
                style: TextStyle(fontSize: 12, color: Colors.grey[600]),
              ),
            const SizedBox(height: 4),
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 2,
                  ),
                  decoration: BoxDecoration(
                    color: _getStatusColor(transaction.status).withOpacity(0.1),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Text(
                    transaction.status.displayName,
                    style: TextStyle(
                      fontSize: 11,
                      color: _getStatusColor(transaction.status),
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
        trailing: Text(
          '${isOutgoing ? '-' : '+'}${formatter.format(transaction.amount)}',
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: isOutgoing ? Colors.red : Colors.green,
          ),
        ),
        isThreeLine: true,
      ),
    );
  }

  Color _getStatusColor(TransactionStatus status) {
    switch (status) {
      case TransactionStatus.completed:
        return Colors.green;
      case TransactionStatus.pending:
        return Colors.orange;
      case TransactionStatus.failed:
        return Colors.red;
      case TransactionStatus.cancelled:
        return Colors.grey;
    }
  }
}
