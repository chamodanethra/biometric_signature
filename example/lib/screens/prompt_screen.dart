import 'package:biometric_signature/biometric_signature.dart';
import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../state/controllers.dart';
import '../state/explorer_state.dart';
import '../widgets/form_widgets.dart';
import '../widgets/result_card.dart';

/// `simplePrompt` with every `SimplePromptConfig` field.
class PromptScreen extends StatelessWidget {
  /// Creates the screen.
  const PromptScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    final c = state.prompt;
    return ListenableBuilder(
      listenable: c,
      builder: (context, _) {
        final busy = c.isBusy(PromptController.promptOp);
        final r = c.result;
        return ScreenList(
          children: [
            const ScreenIntro(
              'simplePrompt shows the system prompt without using a key. It '
              'is a UI gate — the result is a local boolean nobody else can '
              'verify. When a server needs proof, sign a server challenge '
              'instead (Sign screen).',
            ),
            UnexpectedErrorBanner(controller: c),
            SectionCard(
              title: 'Arguments',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  ArgTextField(
                    name: 'promptMessage',
                    platforms: allPlatforms,
                    controller: c.promptMessage,
                    helper: 'Required. Title on Android, localized reason on '
                        'iOS/macOS.',
                  ),
                  ArgTextField(
                    name: 'config.subtitle',
                    platforms: androidOnly,
                    controller: c.subtitle,
                  ),
                  ArgTextField(
                    name: 'config.description',
                    platforms: androidOnly,
                    controller: c.description,
                  ),
                  ArgTextField(
                    name: 'config.cancelButtonText',
                    platforms: androidOnly,
                    controller: c.cancelButtonText,
                  ),
                  OptionSwitch(
                    key: const ValueKey('prompt.allowDeviceCredentials'),
                    name: 'config.allowDeviceCredentials',
                    platforms: mobileAndMac,
                    value: c.allowDeviceCredentials,
                    description: 'Offer the device PIN, pattern or passcode as '
                        'a fallback (iOS/macOS: deviceOwnerAuthentication). '
                        'authenticationType then tells which one was used.',
                    onChanged: busy
                        ? null
                        : (v) => c.update(() => c.allowDeviceCredentials = v),
                  ),
                  EnumChoice<BiometricStrength>(
                    key: const ValueKey('prompt.biometricStrength'),
                    name: 'config.biometricStrength',
                    platforms: androidOnly,
                    values: BiometricStrength.values,
                    selected: c.biometricStrength,
                    onChanged: busy
                        ? null
                        : (v) => c.update(() => c.biometricStrength = v),
                    description: c.biometricStrength == BiometricStrength.weak
                        ? 'weak also accepts Class 2 biometrics (e.g. face '
                            'unlock without depth sensing). Such biometrics '
                            'can never unlock keystore keys.'
                        : 'strong: Class 3 biometrics only — the only kind '
                            'that can unlock keys. If only weak ones are '
                            'enrolled, this reports notEnrolled.',
                  ),
                ],
              ),
            ),
            Align(
              alignment: Alignment.centerRight,
              child: RunButton(
                key: const ValueKey('prompt.run'),
                label: 'simplePrompt',
                icon: Icons.fingerprint,
                busy: busy,
                onPressed: c.show,
              ),
            ),
            if (r != null)
              ResultCard(
                key: const ValueKey('prompt.result'),
                title: 'SimplePromptResult',
                result: r,
                children: [
                  if (r.authenticationType != null)
                    AuthTypeNote(type: r.authenticationType),
                ],
              ),
          ],
        );
      },
    );
  }
}
