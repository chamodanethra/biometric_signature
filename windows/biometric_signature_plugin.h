#ifndef FLUTTER_PLUGIN_BIOMETRIC_SIGNATURE_PLUGIN_H_
#define FLUTTER_PLUGIN_BIOMETRIC_SIGNATURE_PLUGIN_H_

#include <flutter/plugin_registrar_windows.h>
#include "messages.g.h"

#include <memory>
#include <string>

namespace biometric_signature {

class BiometricSignaturePlugin : public flutter::Plugin,
                                  public BiometricSignatureApi {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  BiometricSignaturePlugin();

  virtual ~BiometricSignaturePlugin();

  // Disallow copy and assign.
  BiometricSignaturePlugin(const BiometricSignaturePlugin&) = delete;
  BiometricSignaturePlugin& operator=(const BiometricSignaturePlugin&) = delete;

  // BiometricSignatureApi implementation
  void BiometricAuthAvailable(
      std::function<void(ErrorOr<BiometricAvailability> reply)> result) override;

  void CreateKeys(
      const std::string* key_alias,
      const CreateKeysConfig* config,
      const KeyFormat& key_format,
      const std::string* prompt_message,
      std::function<void(ErrorOr<KeyCreationResult> reply)> result) override;

  void CreateSignature(
      const std::string& payload,
      const std::string* key_alias,
      const CreateSignatureConfig* config,
      const SignatureFormat& signature_format,
      const KeyFormat& key_format,
      const std::string* prompt_message,
      std::function<void(ErrorOr<SignatureResult> reply)> result) override;

  void Decrypt(
      const std::string& payload,
      const std::string* key_alias,
      const PayloadFormat& payload_format,
      const DecryptConfig* config,
      const std::string* prompt_message,
      std::function<void(ErrorOr<DecryptResult> reply)> result) override;

  void DeleteKeys(
      const std::string* key_alias,
      std::function<void(ErrorOr<bool> reply)> result) override;

  void DeleteAllKeys(
      std::function<void(ErrorOr<bool> reply)> result) override;

  void GetKeyInfo(
      const std::string* key_alias,
      bool check_validity,
      const KeyFormat& key_format,
      std::function<void(ErrorOr<KeyInfo> reply)> result) override;

  void SimplePrompt(
      const std::string& prompt_message,
      const SimplePromptConfig* config,
      std::function<void(ErrorOr<SimplePromptResult> reply)> result) override;

  void IsDeviceLockSet(
      std::function<void(ErrorOr<bool> reply)> result) override;
};

}  // namespace biometric_signature

#endif  // FLUTTER_PLUGIN_BIOMETRIC_SIGNATURE_PLUGIN_H_
