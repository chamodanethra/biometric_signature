import 'package:document_signer_example/models/signature_info.dart';

class Document {
  final String id;
  final String title;
  final String content;
  final DateTime createdAt;
  final DateTime? modifiedAt;
  final SignatureInfo? signature;
  final String contentHash;

  Document({
    required this.id,
    required this.title,
    required this.content,
    required this.createdAt,
    this.modifiedAt,
    this.signature,
    required this.contentHash,
  });

  bool get isSigned => signature != null;

  Document copyWith({
    String? id,
    String? title,
    String? content,
    DateTime? createdAt,
    DateTime? modifiedAt,
    SignatureInfo? signature,
    String? contentHash,
  }) {
    return Document(
      id: id ?? this.id,
      title: title ?? this.title,
      content: content ?? this.content,
      createdAt: createdAt ?? this.createdAt,
      modifiedAt: modifiedAt ?? this.modifiedAt,
      signature: signature ?? this.signature,
      contentHash: contentHash ?? this.contentHash,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'title': title,
      'content': content,
      'createdAt': createdAt.toIso8601String(),
      'modifiedAt': modifiedAt?.toIso8601String(),
      'signature': signature?.toJson(),
      'contentHash': contentHash,
    };
  }

  factory Document.fromJson(Map<String, dynamic> json) {
    return Document(
      id: json['id'],
      title: json['title'],
      content: json['content'],
      createdAt: DateTime.parse(json['createdAt']),
      modifiedAt: json['modifiedAt'] != null
          ? DateTime.parse(json['modifiedAt'])
          : null,
      signature: json['signature'] != null
          ? SignatureInfo.fromJson(json['signature'])
          : null,
      contentHash: json['contentHash'],
    );
  }
}
