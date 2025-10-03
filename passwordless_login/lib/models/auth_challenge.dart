class AuthChallenge {
  final String challengeId;
  final String nonce;
  final DateTime expiresAt;
  final String username;

  AuthChallenge({
    required this.challengeId,
    required this.nonce,
    required this.expiresAt,
    required this.username,
  });

  bool get isExpired => DateTime.now().isAfter(expiresAt);

  Map<String, dynamic> toJson() {
    return {
      'challengeId': challengeId,
      'nonce': nonce,
      'expiresAt': expiresAt.toIso8601String(),
      'username': username,
    };
  }

  factory AuthChallenge.fromJson(Map<String, dynamic> json) {
    return AuthChallenge(
      challengeId: json['challengeId'],
      nonce: json['nonce'],
      expiresAt: DateTime.parse(json['expiresAt']),
      username: json['username'],
    );
  }
}

class AuthSession {
  final String sessionId;
  final String userId;
  final DateTime createdAt;
  final DateTime expiresAt;

  AuthSession({
    required this.sessionId,
    required this.userId,
    required this.createdAt,
    required this.expiresAt,
  });

  bool get isValid => DateTime.now().isBefore(expiresAt);

  Map<String, dynamic> toJson() {
    return {
      'sessionId': sessionId,
      'userId': userId,
      'createdAt': createdAt.toIso8601String(),
      'expiresAt': expiresAt.toIso8601String(),
    };
  }

  factory AuthSession.fromJson(Map<String, dynamic> json) {
    return AuthSession(
      sessionId: json['sessionId'],
      userId: json['userId'],
      createdAt: DateTime.parse(json['createdAt']),
      expiresAt: DateTime.parse(json['expiresAt']),
    );
  }
}
