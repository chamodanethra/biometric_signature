import 'package:biometric_signature/biometric_signature.dart';
import 'package:flutter/widgets.dart';

import 'controller_base.dart';

/// Prompt screen: `simplePrompt` with every `SimplePromptConfig` field.
class PromptController extends ExplorerController {
  /// Creates the controller.
  PromptController(super.state);

  /// Operation id for [show].
  static const String promptOp = 'simplePrompt';

  /// `promptMessage`.
  final TextEditingController promptMessage =
      TextEditingController(text: 'Confirm it is you');

  /// `SimplePromptConfig.subtitle`.
  final TextEditingController subtitle = TextEditingController();

  /// `SimplePromptConfig.description`.
  final TextEditingController description = TextEditingController();

  /// `SimplePromptConfig.cancelButtonText`.
  final TextEditingController cancelButtonText = TextEditingController();

  /// `SimplePromptConfig.allowDeviceCredentials`.
  bool allowDeviceCredentials = false;

  /// `SimplePromptConfig.biometricStrength`.
  BiometricStrength biometricStrength = BiometricStrength.strong;

  /// Last result.
  SimplePromptResult? result;

  /// Calls `simplePrompt`.
  Future<void> show() => run(promptOp, () async {
        result = null;
        notifyListeners();
        final message = promptMessage.text.trim().isEmpty
            ? 'Confirm it is you'
            : promptMessage.text;
        result = await api.simplePrompt(
          promptMessage: message,
          config: SimplePromptConfig(
            subtitle: ExplorerController.optionalText(subtitle),
            description: ExplorerController.optionalText(description),
            cancelButtonText: ExplorerController.optionalText(cancelButtonText),
            allowDeviceCredentials: allowDeviceCredentials,
            biometricStrength: biometricStrength,
          ),
        );
      });

  @override
  void dispose() {
    promptMessage.dispose();
    subtitle.dispose();
    description.dispose();
    cancelButtonText.dispose();
    super.dispose();
  }
}
