import 'dart:convert';
import 'package:document_signer_example/models/document.dart';
import 'package:document_signer_example/models/signature_info.dart';
import 'package:document_signer_example/services/signature_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

class DocumentService {
  final SignatureService _signatureService = SignatureService();
  static const String _documentsKey = 'documents';

  /// Get all documents
  Future<List<Document>> getDocuments() async {
    final prefs = await SharedPreferences.getInstance();
    final documentsJson = prefs.getString(_documentsKey);

    if (documentsJson != null) {
      final List<dynamic> decoded = jsonDecode(documentsJson);
      return decoded.map((json) => Document.fromJson(json)).toList();
    }

    return _getSampleDocuments();
  }

  /// Create a new document
  Future<Document> createDocument({
    required String title,
    required String content,
  }) async {
    final document = Document(
      id: DateTime.now().millisecondsSinceEpoch.toString(),
      title: title,
      content: content,
      createdAt: DateTime.now(),
      contentHash: _signatureService.calculateDocumentHash(content),
    );

    await _saveDocument(document);
    return document;
  }

  /// Update a document
  Future<Document> updateDocument(Document document) async {
    final updatedDocument = document.copyWith(
      modifiedAt: DateTime.now(),
      contentHash: _signatureService.calculateDocumentHash(document.content),
      // Clear signature if content changed
      signature: document.contentHash ==
              _signatureService.calculateDocumentHash(document.content)
          ? document.signature
          : null,
    );

    await _saveDocument(updatedDocument);
    return updatedDocument;
  }

  /// Sign a document
  Future<Document> signDocument(Document document) async {
    final signature = await _signatureService.signDocument(document);
    final signedDocument = document.copyWith(signature: signature);
    await _saveDocument(signedDocument);
    return signedDocument;
  }

  /// Delete a document
  Future<void> deleteDocument(String id) async {
    final documents = await getDocuments();
    documents.removeWhere((doc) => doc.id == id);
    await _saveDocuments(documents);
  }

  /// Save a single document
  Future<void> _saveDocument(Document document) async {
    final documents = await getDocuments();
    final index = documents.indexWhere((doc) => doc.id == document.id);

    if (index >= 0) {
      documents[index] = document;
    } else {
      documents.insert(0, document);
    }

    await _saveDocuments(documents);
  }

  /// Save all documents
  Future<void> _saveDocuments(List<Document> documents) async {
    final prefs = await SharedPreferences.getInstance();
    final documentsJson = jsonEncode(
      documents.map((doc) => doc.toJson()).toList(),
    );
    await prefs.setString(_documentsKey, documentsJson);
  }

  /// Get sample documents for demo
  List<Document> _getSampleDocuments() {
    final sampleContent1 = '''
Non-Disclosure Agreement

This Non-Disclosure Agreement (the "Agreement") is entered into as of ${DateTime.now().toString().split(' ')[0]} by and between:

Party A: Example Company Inc.
Party B: John Doe

1. CONFIDENTIAL INFORMATION
   For purposes of this Agreement, "Confidential Information" shall include all information or material that has or could have commercial value or other utility in the business in which Disclosing Party is engaged.

2. NON-DISCLOSURE
   Receiving Party agrees to hold and maintain the Confidential Information in strictest confidence for the sole and exclusive benefit of the Disclosing Party.

3. TERM
   This Agreement shall remain in effect for a period of two (2) years from the date of execution.

Accepted and Agreed:
[Signature Required]
''';

    final sampleContent2 = '''
Service Agreement

Agreement for Professional Services

This Service Agreement is made effective as of ${DateTime.now().toString().split(' ')[0]}.

PARTIES:
Client: ABC Corporation
Service Provider: Professional Services LLC

SERVICES:
The Service Provider agrees to provide the following services:
- Software development consultation
- System architecture design
- Technical documentation

COMPENSATION:
Client agrees to pay Service Provider \$5,000 per month for the services rendered.

TERM:
This agreement shall be effective for 12 months from the date of signing.

[Signature Required]
''';

    return [
      Document(
        id: '1',
        title: 'Non-Disclosure Agreement',
        content: sampleContent1,
        createdAt: DateTime.now().subtract(const Duration(days: 5)),
        contentHash: _signatureService.calculateDocumentHash(sampleContent1),
      ),
      Document(
        id: '2',
        title: 'Service Agreement',
        content: sampleContent2,
        createdAt: DateTime.now().subtract(const Duration(days: 2)),
        contentHash: _signatureService.calculateDocumentHash(sampleContent2),
      ),
    ];
  }

  /// Export document with signature
  String exportDocument(Document document) {
    final export = StringBuffer();

    export.writeln('=== SIGNED DOCUMENT ===\n');
    export.writeln('Title: ${document.title}');
    export.writeln('Created: ${document.createdAt}');
    export.writeln('Document ID: ${document.id}');
    export.writeln('\n--- CONTENT ---\n');
    export.writeln(document.content);

    if (document.isSigned) {
      final sig = document.signature!;
      export.writeln('\n--- DIGITAL SIGNATURE ---\n');
      export.writeln('Signer: ${sig.signerName}');
      export.writeln('Signed At: ${sig.formattedTimestamp}');
      export.writeln('Biometric Method: ${sig.biometricType}');
      export.writeln('Document Hash: ${sig.documentHash}');
      export.writeln('Signature: ${sig.signatureValue.substring(0, 64)}...');
      export.writeln('Public Key: ${sig.signerPublicKey.substring(0, 64)}...');
      export.writeln(
          '\nThis document has been digitally signed and can be verified.');
    } else {
      export.writeln('\n[UNSIGNED DOCUMENT]');
    }

    return export.toString();
  }
}
