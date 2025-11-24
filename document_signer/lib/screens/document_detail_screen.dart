import 'package:document_signer_example/models/document.dart';
import 'package:document_signer_example/services/document_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class DocumentDetailScreen extends StatefulWidget {
  final Document document;

  const DocumentDetailScreen({super.key, required this.document});

  @override
  State<DocumentDetailScreen> createState() => _DocumentDetailScreenState();
}

class _DocumentDetailScreenState extends State<DocumentDetailScreen> {
  final DocumentService _documentService = DocumentService();
  late Document _document;
  bool _isSigning = false;

  @override
  void initState() {
    super.initState();
    _document = widget.document;
  }

  Future<void> _signDocument() async {
    setState(() => _isSigning = true);

    try {
      final signedDoc = await _documentService.signDocument(_document);
      setState(() => _document = signedDoc);

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Document signed successfully!'),
            backgroundColor: Colors.green,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Signing failed: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    } finally {
      setState(() => _isSigning = false);
    }
  }

  void _exportDocument() {
    final exported = _documentService.exportDocument(_document);
    Clipboard.setData(ClipboardData(text: exported));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Document exported to clipboard')),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_document.title),
        actions: [
          if (_document.isSigned)
            IconButton(
              icon: const Icon(Icons.share),
              onPressed: _exportDocument,
            ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (_document.isSigned)
              Card(
                color: Colors.green.withOpacity(0.1),
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Row(
                        children: [
                          Icon(Icons.verified, color: Colors.green),
                          SizedBox(width: 8),
                          Text(
                            'Digitally Signed',
                            style: TextStyle(
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      _buildSignatureInfo(),
                    ],
                  ),
                ),
              ),
            const SizedBox(height: 16),
            const Text(
              'Document Content',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            Text(_document.content),
          ],
        ),
      ),
      bottomNavigationBar: !_document.isSigned
          ? SafeArea(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: ElevatedButton(
                  onPressed: _isSigning ? null : _signDocument,
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  child: _isSigning
                      ? const CircularProgressIndicator()
                      : const Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(Icons.fingerprint),
                            SizedBox(width: 8),
                            Text('Sign Document'),
                          ],
                        ),
                ),
              ),
            )
          : null,
    );
  }

  Widget _buildSignatureInfo() {
    final sig = _document.signature!;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _buildInfoRow('Signer', sig.signerName),
        _buildInfoRow('Signed At', sig.formattedTimestamp),
        _buildInfoRow('Method', sig.biometricType),
        _buildInfoRow(
          'Document Hash',
          sig.documentHash.substring(0, 32) + '...',
        ),
      ],
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text('$label:', style: TextStyle(color: Colors.grey[700])),
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
}
