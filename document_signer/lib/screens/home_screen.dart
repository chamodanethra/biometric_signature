import 'package:flutter/material.dart';
import 'package:document_signer_example/models/document.dart';
import 'package:document_signer_example/services/document_service.dart';
import 'package:document_signer_example/services/signature_service.dart';
import 'package:document_signer_example/screens/document_detail_screen.dart';
import 'package:document_signer_example/screens/create_document_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final DocumentService _documentService = DocumentService();
  final SignatureService _signatureService = SignatureService();

  List<Document> _documents = [];
  bool _isLoading = true;
  bool _isInitialized = false;

  @override
  void initState() {
    super.initState();
    _initialize();
  }

  Future<void> _initialize() async {
    setState(() => _isLoading = true);

    try {
      // Check biometric availability
      final isAvailable = await _signatureService.isBiometricAvailable();

      if (!isAvailable) {
        _showError('Biometric authentication is not available');
        setState(() => _isLoading = false);
        return;
      }

      // Check if keys exist
      final hasKeys = await _signatureService.hasKeys();

      if (!hasKeys) {
        await _setupBiometrics();
      }

      // Load documents
      await _loadDocuments();

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
    // Get signer name
    final nameController = TextEditingController();
    final name = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: const Text('Setup Document Signing'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Enter your name for document signatures:'),
            const SizedBox(height: 16),
            TextField(
              controller: nameController,
              decoration: const InputDecoration(
                labelText: 'Full Name',
                border: OutlineInputBorder(),
              ),
              autofocus: true,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, nameController.text),
            child: const Text('Continue'),
          ),
        ],
      ),
    );

    if (name == null || name.isEmpty) {
      if (mounted) Navigator.of(context).pop();
      return;
    }

    try {
      await _signatureService.setSignerName(name);
      await _signatureService.initializeKeys();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Setup successful! You can now sign documents.'),
            backgroundColor: Colors.green,
          ),
        );
      }
    } catch (e) {
      _showError('Setup failed: $e');
      if (mounted) Navigator.of(context).pop();
    }
  }

  Future<void> _loadDocuments() async {
    final documents = await _documentService.getDocuments();
    setState(() => _documents = documents);
  }

  void _showError(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: Colors.red),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Document Signer'),
        actions: [
          IconButton(
            icon: const Icon(Icons.person),
            onPressed: () async {
              final name = await _signatureService.getSignerName();
              if (mounted) {
                showDialog(
                  context: context,
                  builder: (context) => AlertDialog(
                    title: const Text('Signer Info'),
                    content: Text('Signed as: $name'),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.pop(context),
                        child: const Text('OK'),
                      ),
                    ],
                  ),
                );
              }
            },
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : !_isInitialized
              ? const Center(
                  child: Text('Biometric authentication not available'))
              : RefreshIndicator(
                  onRefresh: _loadDocuments,
                  child: _documents.isEmpty
                      ? const Center(child: Text('No documents yet'))
                      : ListView.builder(
                          padding: const EdgeInsets.all(16),
                          itemCount: _documents.length,
                          itemBuilder: (context, index) {
                            final doc = _documents[index];
                            return Card(
                              margin: const EdgeInsets.only(bottom: 12),
                              child: ListTile(
                                leading: CircleAvatar(
                                  backgroundColor: doc.isSigned
                                      ? Colors.green.withOpacity(0.2)
                                      : Colors.orange.withOpacity(0.2),
                                  child: Icon(
                                    doc.isSigned
                                        ? Icons.verified
                                        : Icons.pending,
                                    color: doc.isSigned
                                        ? Colors.green
                                        : Colors.orange,
                                  ),
                                ),
                                title: Text(doc.title),
                                subtitle: Text(
                                  doc.isSigned
                                      ? 'Signed ${doc.signature!.formattedTimestamp}'
                                      : 'Unsigned',
                                ),
                                trailing: const Icon(
                                  Icons.arrow_forward_ios,
                                  size: 16,
                                ),
                                onTap: () => _openDocument(doc),
                              ),
                            );
                          },
                        ),
                ),
      floatingActionButton: _isInitialized
          ? FloatingActionButton.extended(
              onPressed: _createDocument,
              icon: const Icon(Icons.add),
              label: const Text('New Document'),
            )
          : null,
    );
  }

  void _openDocument(Document doc) async {
    final result = await Navigator.push<bool>(
      context,
      MaterialPageRoute(
        builder: (context) => DocumentDetailScreen(document: doc),
      ),
    );

    if (result == true) {
      await _loadDocuments();
    }
  }

  void _createDocument() async {
    final result = await Navigator.push<bool>(
      context,
      MaterialPageRoute(builder: (context) => const CreateDocumentScreen()),
    );

    if (result == true) {
      await _loadDocuments();
    }
  }
}
