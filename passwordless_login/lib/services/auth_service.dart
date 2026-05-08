import 'dart:convert';
import 'dart:math';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:passwordless_login_example/models/auth_challenge.dart';
import 'package:passwordless_login_example/models/user.dart';
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
    bool allowDeviceCredentials = false,
    bool keyInvalidatedOnEnrollmentChange = true,
  }) async {
    // Check if username already exists
    final users = await _getAllUsers();
    if (users.any((u) => u.username == username)) {
      throw Exception('Username already exists');
    }

    // Generate biometric keys
    final keyResult = await _biometric.createKeys(
      keyFormat: KeyFormat.base64,
      promptMessage: 'Set up biometric authentication',
      config: CreateKeysConfig(
        useDeviceCredentials: allowDeviceCredentials,
        signatureType: SignatureType.rsa,
        enforceBiometric: true,
        setInvalidatedByBiometricEnrollment: keyInvalidatedOnEnrollmentChange,
      ),
    );

    if (keyResult.code != BiometricError.success) {
      throw Exception(
        'Failed to generate cryptographic keys: ${keyResult.error ?? keyResult.code}',
      );
    }

    final publicKey = keyResult.publicKey;
    if (publicKey == null) {
      throw Exception('Public key is null after successful key creation');
    }

    // Create user
    final user = User(
      id: DateTime.now().millisecondsSinceEpoch.toString(),
      username: username,
      email: email,
      publicKey: publicKey,
      createdAt: DateTime.now(),
      allowDeviceCredentials: allowDeviceCredentials,
      keyInvalidatedOnEnrollmentChange: keyInvalidatedOnEnrollmentChange,
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
  /// Returns SignatureResult to allow UI to handle specific error codes
  Future<SignatureResult> authenticateWithChallenge({
    required String username,
    required String challengeId,
  }) async {
    // Get stored challenge
    final challenge = await _getChallenge(challengeId);
    if (challenge == null) {
      return SignatureResult(
        code: BiometricError.unknown,
        error: 'Challenge not found or expired',
      );
    }

    if (challenge.isExpired) {
      await _removeChallenge(challengeId);
      return SignatureResult(
        code: BiometricError.unknown,
        error: 'Challenge expired',
      );
    }

    if (challenge.username != username) {
      return SignatureResult(
        code: BiometricError.unknown,
        error: 'Challenge username mismatch',
      );
    }

    // Get user to check device credential settings
    final users = await _getAllUsers();
    final user = users.where((u) => u.username == username).firstOrNull;
    if (user == null) {
      return SignatureResult(
        code: BiometricError.unknown,
        error: 'User not found',
      );
    }

    // Sign challenge with biometric
    final signatureResult = await _biometric.createSignature(
      payload: challenge.nonce,
      promptMessage: 'Login as $username',
      signatureFormat: SignatureFormat.base64,
      keyFormat: KeyFormat.base64,
      config: CreateSignatureConfig(
        cancelButtonText: 'Cancel',
        allowDeviceCredentials: user.allowDeviceCredentials,
        shouldMigrate: false,
      ),
    );

    // Return the result directly - let UI handle errors
    if (signatureResult.code != BiometricError.success) {
      return signatureResult;
    }

    final signature = signatureResult.signature;
    if (signature == null) {
      return SignatureResult(
        code: BiometricError.unknown,
        error: 'Signature is null despite success code',
      );
    }

    // In production, send signature to server for verification
    // Server would verify using stored public key
    final isValid = await _verifySignature(
      username,
      challenge.nonce,
      signature,
    );

    if (!isValid) {
      return SignatureResult(
        code: BiometricError.unknown,
        error: 'Signature verification failed',
      );
    }

    // Remove used challenge
    await _removeChallenge(challengeId);

    // Update last login
    final updatedUser = user.copyWith(lastLogin: DateTime.now());
    await _updateUser(updatedUser);

    return signatureResult;
  }

  /// Complete authentication - convenience wrapper that creates session
  Future<AuthSession> authenticate({
    required String username,
    required String challengeId,
  }) async {
    final result = await authenticateWithChallenge(
      username: username,
      challengeId: challengeId,
    );

    if (result.code != BiometricError.success) {
      throw Exception('Authentication failed: ${result.error ?? result.code}');
    }

    // Create session
    return await createSession(username);
  }

  /// Create a new session for the user
  /// Should only be called after successful authentication
  Future<AuthSession> createSession(String username) async {
    // Get user
    final users = await _getAllUsers();
    final user = users.firstWhere((u) => u.username == username);

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

  /// Re-enroll biometrics after key invalidation
  /// Deletes old keys and creates new ones
  Future<User> reEnrollBiometrics(String username) async {
    final users = await _getAllUsers();
    final user = users.where((u) => u.username == username).firstOrNull;

    if (user == null) {
      throw Exception('User not found');
    }

    // Delete existing keys
    await _biometric.deleteKeys();

    // Create new keys with same settings
    final keyResult = await _biometric.createKeys(
      keyFormat: KeyFormat.base64,
      promptMessage: 'Re-enroll biometric authentication',
      config: CreateKeysConfig(
        useDeviceCredentials: user.allowDeviceCredentials,
        signatureType: SignatureType.rsa,
        enforceBiometric: true,
        setInvalidatedByBiometricEnrollment:
            user.keyInvalidatedOnEnrollmentChange,
      ),
    );

    if (keyResult.code != BiometricError.success) {
      throw Exception(
        'Failed to create new keys: ${keyResult.error ?? keyResult.code}',
      );
    }

    final publicKey = keyResult.publicKey;
    if (publicKey == null) {
      throw Exception('Public key is null after successful key creation');
    }

    // Update user with new public key
    final updatedUser = user.copyWith(
      publicKey: publicKey,
      lastReEnrollment: DateTime.now(),
    );

    await _updateUser(updatedUser);

    return updatedUser;
  }

  /// Get current biometric availability status
  Future<BiometricAvailability> getBiometricStatus() async {
    return await _biometric.biometricAuthAvailable();
  }

  /// Check if biometric key exists and is valid
  Future<KeyInfo> getKeyStatus() async {
    return await _biometric.getKeyInfo(
      checkValidity: true,
      keyFormat: KeyFormat.base64,
    );
  }

  /// Delete biometric keys
  Future<bool> deleteKeys() async {
    return await _biometric.deleteKeys();
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
    return decoded.map((k, v) => MapEntry(k, AuthChallenge.fromJson(v)));
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
