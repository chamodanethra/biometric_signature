import 'dart:convert';
import 'dart:math';
import 'package:passwordless_login_example/models/user.dart';
import 'package:passwordless_login_example/models/auth_challenge.dart';
import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/signature_options.dart';
import 'package:biometric_signature/android_config.dart';
import 'package:biometric_signature/ios_config.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Simulates a backend authentication service
/// In production, replace with actual REST API calls
class AuthService {
  final BiometricSignature _biometric = BiometricSignature();
  static const String _usersKey = 'users_db';
  static const String _sessionKey = 'current_session';
  static const String _challengesKey = 'auth_challenges';

  /// Register a new user
  Future<User> register({
    required String username,
    required String email,
  }) async {
    // Check if username already exists
    final users = await _getAllUsers();
    if (users.any((u) => u.username == username)) {
      throw Exception('Username already exists');
    }

    // Generate biometric keys
    final keyResult = await _biometric.createKeys(
      androidConfig: AndroidConfig(
        useDeviceCredentials: false,
        signatureType: AndroidSignatureType.RSA,
      ),
      iosConfig: IosConfig(
        useDeviceCredentials: false,
        signatureType: IOSSignatureType.RSA,
      ),
    );

    if (keyResult == null) {
      throw Exception('Failed to generate cryptographic keys');
    }

    final publicKey = keyResult.publicKey.toBase64();

    // Create user
    final user = User(
      id: DateTime.now().millisecondsSinceEpoch.toString(),
      username: username,
      email: email,
      publicKey: publicKey,
      createdAt: DateTime.now(),
    );

    // Save to "database"
    users.add(user);
    await _saveUsers(users);

    return user;
  }

  /// Request login challenge
  Future<AuthChallenge> requestChallenge(String username) async {
    final users = await _getAllUsers();
    final user = users.where((u) => u.username == username).firstOrNull;

    if (user == null) {
      throw Exception('User not found');
    }

    // Generate random nonce
    final random = Random.secure();
    final nonceBytes = List<int>.generate(32, (i) => random.nextInt(256));
    final nonce = base64Url.encode(nonceBytes);

    // Create challenge
    final challenge = AuthChallenge(
      challengeId: DateTime.now().millisecondsSinceEpoch.toString(),
      nonce: nonce,
      expiresAt: DateTime.now().add(const Duration(minutes: 5)),
      username: username,
    );

    // Store challenge
    await _storeChallenge(challenge);

    return challenge;
  }

  /// Complete authentication with signed challenge
  Future<AuthSession> authenticate({
    required String username,
    required String challengeId,
  }) async {
    // Get stored challenge
    final challenge = await _getChallenge(challengeId);
    if (challenge == null) {
      throw Exception('Challenge not found or expired');
    }

    if (challenge.isExpired) {
      await _removeChallenge(challengeId);
      throw Exception('Challenge expired');
    }

    if (challenge.username != username) {
      throw Exception('Challenge username mismatch');
    }

    // Sign challenge with biometric
    final signatureResult = await _biometric.createSignature(
      SignatureOptions(
        payload: challenge.nonce,
        promptMessage: 'Login as $username',
        androidOptions: const AndroidSignatureOptions(
          cancelButtonText: 'Cancel',
          allowDeviceCredentials: false,
        ),
        iosOptions: const IosSignatureOptions(
          shouldMigrate: false,
        ),
      ),
    );

    final signature = signatureResult?.signature.toBase64();

    if (signature == null) {
      throw Exception('Authentication failed');
    }

    // In production, send signature to server for verification
    // Server would verify using stored public key
    final isValid =
        await _verifySignature(username, challenge.nonce, signature);

    if (!isValid) {
      throw Exception('Signature verification failed');
    }

    // Remove used challenge
    await _removeChallenge(challengeId);

    // Get user
    final users = await _getAllUsers();
    final user = users.firstWhere((u) => u.username == username);

    // Update last login
    final updatedUser = user.copyWith(lastLogin: DateTime.now());
    await _updateUser(updatedUser);

    // Create session
    final session = AuthSession(
      sessionId: _generateSessionId(),
      userId: user.id,
      createdAt: DateTime.now(),
      expiresAt: DateTime.now().add(const Duration(days: 7)),
    );

    await _saveSession(session);

    return session;
  }

  /// Verify signature (simulated server-side verification)
  Future<bool> _verifySignature(
    String username,
    String nonce,
    String signature,
  ) async {
    // In production, this would be done on the server:
    // 1. Retrieve user's public key from database
    // 2. Verify signature using public key and nonce
    // 3. Return verification result

    // For this demo, we just check that signature is not empty
    return signature.isNotEmpty;
  }

  /// Check if user has active session
  Future<AuthSession?> getCurrentSession() async {
    final prefs = await SharedPreferences.getInstance();
    final sessionJson = prefs.getString(_sessionKey);

    if (sessionJson == null) return null;

    final session = AuthSession.fromJson(jsonDecode(sessionJson));

    if (!session.isValid) {
      await logout();
      return null;
    }

    return session;
  }

  /// Logout
  Future<void> logout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_sessionKey);
  }

  /// Check if username is available
  Future<bool> isUsernameAvailable(String username) async {
    final users = await _getAllUsers();
    return !users.any((u) => u.username == username);
  }

  /// Get current user
  Future<User?> getCurrentUser() async {
    final session = await getCurrentSession();
    if (session == null) return null;

    final users = await _getAllUsers();
    return users.where((u) => u.id == session.userId).firstOrNull;
  }

  // Helper methods

  Future<List<User>> _getAllUsers() async {
    final prefs = await SharedPreferences.getInstance();
    final usersJson = prefs.getString(_usersKey);

    if (usersJson == null) return [];

    final List<dynamic> decoded = jsonDecode(usersJson);
    return decoded.map((json) => User.fromJson(json)).toList();
  }

  Future<void> _saveUsers(List<User> users) async {
    final prefs = await SharedPreferences.getInstance();
    final usersJson = jsonEncode(users.map((u) => u.toJson()).toList());
    await prefs.setString(_usersKey, usersJson);
  }

  Future<void> _updateUser(User user) async {
    final users = await _getAllUsers();
    final index = users.indexWhere((u) => u.id == user.id);
    if (index >= 0) {
      users[index] = user;
      await _saveUsers(users);
    }
  }

  Future<void> _storeChallenge(AuthChallenge challenge) async {
    final prefs = await SharedPreferences.getInstance();
    final challenges = await _getAllChallenges();
    challenges[challenge.challengeId] = challenge;

    // Clean expired challenges
    challenges.removeWhere((_, c) => c.isExpired);

    final challengesJson = jsonEncode(
      challenges.map((k, v) => MapEntry(k, v.toJson())),
    );
    await prefs.setString(_challengesKey, challengesJson);
  }

  Future<AuthChallenge?> _getChallenge(String challengeId) async {
    final challenges = await _getAllChallenges();
    return challenges[challengeId];
  }

  Future<void> _removeChallenge(String challengeId) async {
    final prefs = await SharedPreferences.getInstance();
    final challenges = await _getAllChallenges();
    challenges.remove(challengeId);

    final challengesJson = jsonEncode(
      challenges.map((k, v) => MapEntry(k, v.toJson())),
    );
    await prefs.setString(_challengesKey, challengesJson);
  }

  Future<Map<String, AuthChallenge>> _getAllChallenges() async {
    final prefs = await SharedPreferences.getInstance();
    final challengesJson = prefs.getString(_challengesKey);

    if (challengesJson == null) return {};

    final Map<String, dynamic> decoded = jsonDecode(challengesJson);
    return decoded.map(
      (k, v) => MapEntry(k, AuthChallenge.fromJson(v)),
    );
  }

  Future<void> _saveSession(AuthSession session) async {
    final prefs = await SharedPreferences.getInstance();
    final sessionJson = jsonEncode(session.toJson());
    await prefs.setString(_sessionKey, sessionJson);
  }

  String _generateSessionId() {
    final random = Random.secure();
    final bytes = List<int>.generate(32, (i) => random.nextInt(256));
    return base64Url.encode(bytes);
  }
}
