class User {
  final String id;
  final String username;
  final String email;
  final String publicKey;
  final DateTime createdAt;
  final DateTime? lastLogin;
  final bool allowDeviceCredentials;
  final bool keyInvalidatedOnEnrollmentChange;
  final DateTime? lastReEnrollment;

  User({
    required this.id,
    required this.username,
    required this.email,
    required this.publicKey,
    required this.createdAt,
    this.lastLogin,
    this.allowDeviceCredentials = false,
    this.keyInvalidatedOnEnrollmentChange = true,
    this.lastReEnrollment,
  });

  User copyWith({
    String? id,
    String? username,
    String? email,
    String? publicKey,
    DateTime? createdAt,
    DateTime? lastLogin,
    bool? allowDeviceCredentials,
    bool? keyInvalidatedOnEnrollmentChange,
    DateTime? lastReEnrollment,
  }) {
    return User(
      id: id ?? this.id,
      username: username ?? this.username,
      email: email ?? this.email,
      publicKey: publicKey ?? this.publicKey,
      createdAt: createdAt ?? this.createdAt,
      lastLogin: lastLogin ?? this.lastLogin,
      allowDeviceCredentials:
          allowDeviceCredentials ?? this.allowDeviceCredentials,
      keyInvalidatedOnEnrollmentChange: keyInvalidatedOnEnrollmentChange ??
          this.keyInvalidatedOnEnrollmentChange,
      lastReEnrollment: lastReEnrollment ?? this.lastReEnrollment,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'username': username,
      'email': email,
      'publicKey': publicKey,
      'createdAt': createdAt.toIso8601String(),
      'lastLogin': lastLogin?.toIso8601String(),
      'allowDeviceCredentials': allowDeviceCredentials,
      'keyInvalidatedOnEnrollmentChange': keyInvalidatedOnEnrollmentChange,
      'lastReEnrollment': lastReEnrollment?.toIso8601String(),
    };
  }

  factory User.fromJson(Map<String, dynamic> json) {
    return User(
      id: json['id'],
      username: json['username'],
      email: json['email'],
      publicKey: json['publicKey'],
      createdAt: DateTime.parse(json['createdAt']),
      lastLogin:
          json['lastLogin'] != null ? DateTime.parse(json['lastLogin']) : null,
      allowDeviceCredentials: json['allowDeviceCredentials'] ?? false,
      keyInvalidatedOnEnrollmentChange:
          json['keyInvalidatedOnEnrollmentChange'] ?? true,
      lastReEnrollment: json['lastReEnrollment'] != null
          ? DateTime.parse(json['lastReEnrollment'])
          : null,
    );
  }
}
