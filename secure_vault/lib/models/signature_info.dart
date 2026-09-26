class SignatureInfo {
  final String signatureValue;
  final DateTime timestamp;
  final String signerPublicKey;
  final String documentHash;
  final String biometricType;
  final String signerName;

  SignatureInfo({
    required this.signatureValue,
    required this.timestamp,
    required this.signerPublicKey,
    required this.documentHash,
    required this.biometricType,
    required this.signerName,
  });

  Map<String, dynamic> toJson() {
    return {
      'signatureValue': signatureValue,
      'timestamp': timestamp.toIso8601String(),
      'signerPublicKey': signerPublicKey,
      'documentHash': documentHash,
      'biometricType': biometricType,
      'signerName': signerName,
    };
  }

  factory SignatureInfo.fromJson(Map<String, dynamic> json) {
    return SignatureInfo(
      signatureValue: json['signatureValue'],
      timestamp: DateTime.parse(json['timestamp']),
      signerPublicKey: json['signerPublicKey'],
      documentHash: json['documentHash'],
      biometricType: json['biometricType'],
      signerName: json['signerName'],
    );
  }

  String get formattedTimestamp {
    return '${timestamp.year}-${timestamp.month.toString().padLeft(2, '0')}-'
        '${timestamp.day.toString().padLeft(2, '0')} '
        '${timestamp.hour.toString().padLeft(2, '0')}:'
        '${timestamp.minute.toString().padLeft(2, '0')}:'
        '${timestamp.second.toString().padLeft(2, '0')}';
  }
}
