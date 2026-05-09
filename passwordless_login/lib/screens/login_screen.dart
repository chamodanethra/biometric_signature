import 'package:biometric_signature/biometric_signature.dart';
import 'package:flutter/material.dart';
import 'package:passwordless_login_example/screens/home_screen.dart';
import 'package:passwordless_login_example/screens/register_screen.dart';
import 'package:passwordless_login_example/services/auth_service.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final AuthService _authService = AuthService();
  final _usernameController = TextEditingController();
  bool _isLoading = false;

  @override
  void dispose() {
    _usernameController.dispose();
    super.dispose();
  }

  Future<void> _login() async {
    final username = _usernameController.text.trim();

    if (username.isEmpty) {
      _showError('Please enter your username');
      return;
    }

    setState(() => _isLoading = true);

    try {
      // Request challenge from server
      final challenge = await _authService.requestChallenge(username);

      // Authenticate with biometric (signs the challenge)
      final result = await _authService.authenticateWithChallenge(
        username: username,
        challengeId: challenge.challengeId,
      );

      // Handle different error codes
      if (result.code != BiometricError.success) {
        await _handleBiometricError(result, username);
        setState(() => _isLoading = false);
        return;
      }

      // Success - create session and navigate
      await _authService.createSession(username);

      if (mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => const HomeScreen()),
        );
      }
    } catch (e) {
      _showError(e.toString());
      setState(() => _isLoading = false);
    }
  }

  Future<void> _handleBiometricError(
    SignatureResult result,
    String username,
  ) async {
    switch (result.code) {
      case BiometricError.userCanceled:
        _showSnackBar('Authentication cancelled');
        break;

      case BiometricError.keyInvalidated:
        final reEnroll = await _showReEnrollDialog();
        if (reEnroll == true && mounted) {
          await _performReEnrollment(username);
        }
        break;

      case BiometricError.lockedOut:
        await _showLockedOutDialog(temporary: true);
        break;

      case BiometricError.lockedOutPermanent:
        await _showLockedOutDialog(temporary: false);
        break;

      case BiometricError.notEnrolled:
        await _showNotEnrolledDialog();
        break;

      case BiometricError.notAvailable:
        await _showNotAvailableDialog();
        break;

      case BiometricError.keyNotFound:
        await _showKeyNotFoundDialog(username);
        break;

      default:
        _showError('Authentication failed: ${result.error ?? result.code}');
    }
  }

  Future<bool?> _showReEnrollDialog() {
    return showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: Colors.orange),
            SizedBox(width: 12),
            Text('Key Invalidated'),
          ],
        ),
        content: const Text(
          'Your biometric key has been invalidated due to changes in enrolled '
          'biometrics (e.g., adding a new fingerprint or face).\n\n'
          'You need to re-enroll to continue using biometric authentication.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Re-enroll'),
          ),
        ],
      ),
    );
  }

  Future<void> _performReEnrollment(String username) async {
    setState(() => _isLoading = true);
    try {
      await _authService.reEnrollBiometrics(username);
      _showSnackBar('Biometric re-enrollment successful! Please login again.');
    } catch (e) {
      _showError('Re-enrollment failed: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _showLockedOutDialog({required bool temporary}) {
    return showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.lock_clock,
                color: temporary ? Colors.orange : Colors.red),
            const SizedBox(width: 12),
            Text(temporary ? 'Temporarily Locked Out' : 'Locked Out'),
          ],
        ),
        content: Text(
          temporary
              ? 'Too many failed biometric attempts. Please wait a moment '
                  'before trying again, or use your device passcode if enabled.'
              : 'You are locked out due to too many failed attempts. You must '
                  'authenticate with your device passcode/PIN to unlock biometric authentication.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  Future<void> _showNotEnrolledDialog() {
    return showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.fingerprint_outlined, color: Colors.orange),
            SizedBox(width: 12),
            Text('No Biometrics Enrolled'),
          ],
        ),
        content: const Text(
          'No fingerprints or face data are enrolled on this device.\n\n'
          'Please go to your device Settings and enroll at least one biometric '
          'before using this authentication method.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  Future<void> _showNotAvailableDialog() {
    return showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.error_outline, color: Colors.red),
            SizedBox(width: 12),
            Text('Biometrics Not Available'),
          ],
        ),
        content: const Text(
          'Biometric authentication is not available on this device.\n\n'
          'This could be because:\n'
          '• The device has no biometric hardware\n'
          '• Biometrics are disabled in settings\n'
          '• The device is not secure (no lock screen)',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  Future<void> _showKeyNotFoundDialog(String username) {
    return showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.key_off, color: Colors.orange),
            SizedBox(width: 12),
            Text('Key Not Found'),
          ],
        ),
        content: const Text(
          'No biometric key found for your account.\n\n'
          'You may need to re-enroll your biometric authentication.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              Navigator.pop(context);
              await _performReEnrollment(username);
            },
            child: const Text('Re-enroll'),
          ),
        ],
      ),
    );
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: Colors.red),
    );
  }

  void _showSnackBar(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(
                  Icons.fingerprint,
                  size: 80,
                  color: Theme.of(context).primaryColor,
                ),
                const SizedBox(height: 24),
                const Text(
                  'Welcome Back',
                  style: TextStyle(fontSize: 32, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 8),
                Text(
                  'Login with your biometrics',
                  style: TextStyle(fontSize: 16, color: Colors.grey[600]),
                ),
                const SizedBox(height: 48),
                TextField(
                  controller: _usernameController,
                  decoration: const InputDecoration(
                    labelText: 'Username',
                    prefixIcon: Icon(Icons.person),
                  ),
                  enabled: !_isLoading,
                  onSubmitted: (_) => _login(),
                ),
                const SizedBox(height: 24),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _isLoading ? null : _login,
                    child: _isLoading
                        ? const SizedBox(
                            height: 20,
                            width: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Icon(Icons.fingerprint),
                              SizedBox(width: 8),
                              Text('Login', style: TextStyle(fontSize: 16)),
                            ],
                          ),
                  ),
                ),
                const SizedBox(height: 32),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(
                      'Don\'t have an account? ',
                      style: TextStyle(color: Colors.grey[600]),
                    ),
                    TextButton(
                      onPressed: () {
                        Navigator.of(context).push(
                          MaterialPageRoute(
                            builder: (context) => const RegisterScreen(),
                          ),
                        );
                      },
                      child: const Text('Register'),
                    ),
                  ],
                ),
                const SizedBox(height: 48),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.blue.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: Colors.blue.withOpacity(0.3)),
                  ),
                  child: Column(
                    children: [
                      const Row(
                        children: [
                          Icon(Icons.security, size: 20, color: Colors.blue),
                          SizedBox(width: 8),
                          Text(
                            'Secure & Passwordless',
                            style: TextStyle(fontWeight: FontWeight.w500),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Your biometric data never leaves your device. '
                        'We use cryptographic signatures for authentication.',
                        style: TextStyle(fontSize: 12, color: Colors.grey[700]),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
