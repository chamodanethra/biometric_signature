#include "biometric_signature_plugin.h"

#include <objbase.h>
#include <windows.h>



// C++/WinRT Windows Hello APIs
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.Storage.Streams.h>

#include <flutter/plugin_registrar_windows.h>

#include <functional>
#include <iomanip>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>


// Base64 encoding utility
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

namespace biometric_signature {

namespace {

// Default key name for Windows Hello credential
const std::wstring kDefaultKeyName = L"BiometricSignatureKey";
const std::wstring kAliasMarkerPrefix = L"BiometricSignatureAlias::";
const std::wstring kDefaultAliasMarker = L"__default__";

// Compute the Windows Hello key name from an optional alias
std::wstring KeyNameForAlias(const std::string* key_alias) {
  if (key_alias == nullptr || key_alias->empty()) {
    return kDefaultKeyName;
  }
  std::wstring wide_alias(key_alias->begin(), key_alias->end());
  return L"BiometricSignatureKey_" + wide_alias;
}

std::wstring AliasMarkerFromOptionalAlias(const std::string* key_alias) {
  if (key_alias == nullptr || key_alias->empty()) {
    return kDefaultAliasMarker;
  }
  return std::wstring(key_alias->begin(), key_alias->end());
}

std::wstring KeyNameFromAliasMarker(const std::wstring& marker) {
  if (marker == kDefaultAliasMarker) {
    return kDefaultKeyName;
  }
  return L"BiometricSignatureKey_" + marker;
}

void TrackAliasMarker(const std::wstring& marker) {
  auto values = winrt::Windows::Storage::ApplicationData::Current()
          .LocalSettings()
          .Values();
  values.Insert(winrt::hstring(kAliasMarkerPrefix + marker), winrt::box_value(true));
}

void UntrackAliasMarker(const std::wstring& marker) {
  auto values = winrt::Windows::Storage::ApplicationData::Current()
          .LocalSettings()
          .Values();
  values.TryRemove(winrt::hstring(kAliasMarkerPrefix + marker));
}

std::vector<std::wstring> TrackedKeyNames() {
  std::set<std::wstring> key_names;
  key_names.insert(kDefaultKeyName);

  auto values = winrt::Windows::Storage::ApplicationData::Current()
          .LocalSettings()
          .Values();

  for (auto const& entry : values) {
    std::wstring key(entry.Key().c_str());
    if (key.rfind(kAliasMarkerPrefix, 0) != 0) {
      continue;
    }
    std::wstring marker = key.substr(kAliasMarkerPrefix.size());
    key_names.insert(KeyNameFromAliasMarker(marker));
  }

  return std::vector<std::wstring>(key_names.begin(), key_names.end());
}

void ClearTrackedAliasMarkers() {
  auto values = winrt::Windows::Storage::ApplicationData::Current()
          .LocalSettings()
          .Values();

  std::vector<winrt::hstring> keys_to_remove;
  for (auto const& entry : values) {
    std::wstring key(entry.Key().c_str());
    if (key.rfind(kAliasMarkerPrefix, 0) == 0) {
      keys_to_remove.push_back(entry.Key());
    }
  }

  for (auto const& key : keys_to_remove) {
    values.TryRemove(key);
  }
}

// Base64 encode bytes
std::string Base64Encode(const std::vector<uint8_t> &data) {
  if (data.empty())
    return "";
  DWORD size = 0;
  CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
                       CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr,
                       &size);
  std::string result(size, 0);
  CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
                       CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0],
                       &size);
  if (!result.empty() && result.back() == '\0') {
    result.pop_back();
  }
  return result;
}

// Hex encode bytes
std::string HexEncode(const std::vector<uint8_t> &data) {
  if (data.empty())
    return "";
  std::ostringstream oss;
  for (uint8_t byte : data) {
    oss << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<int>(byte);
  }
  return oss.str();
}

// Format public key according to the requested format
std::string FormatPublicKey(const std::vector<uint8_t> &key_bytes,
                            KeyFormat key_format) {
  std::string base64_key = Base64Encode(key_bytes);

  switch (key_format) {
  case KeyFormat::kBase64:
  case KeyFormat::kRaw:
    return base64_key;
  case KeyFormat::kPem: {
    std::string pem = "-----BEGIN PUBLIC KEY-----\n";
    for (size_t i = 0; i < base64_key.length(); i += 64) {
      pem += base64_key.substr(i, 64) + "\n";
    }
    pem += "-----END PUBLIC KEY-----";
    return pem;
  }
  case KeyFormat::kHex:
    return HexEncode(key_bytes);
  default:
    return base64_key;
  }
}

// Format signature according to the requested format
std::string FormatSignature(const std::vector<uint8_t> &sig_bytes,
                            SignatureFormat sig_format) {
  switch (sig_format) {
  case SignatureFormat::kBase64:
  case SignatureFormat::kRaw:
    return Base64Encode(sig_bytes);
  case SignatureFormat::kHex:
    return HexEncode(sig_bytes);
  default:
    return Base64Encode(sig_bytes);
  }
}

// Convert IBuffer to vector
std::vector<uint8_t>
IBufferToVector(const winrt::Windows::Storage::Streams::IBuffer &buffer) {
  auto reader =
      winrt::Windows::Storage::Streams::DataReader::FromBuffer(buffer);
  std::vector<uint8_t> data(buffer.Length());
  reader.ReadBytes(data);
  return data;
}

// Convert vector to IBuffer
winrt::Windows::Storage::Streams::IBuffer
VectorToIBuffer(const std::vector<uint8_t> &data) {
  auto writer = winrt::Windows::Storage::Streams::DataWriter();
  writer.WriteBytes(data);
  return writer.DetachBuffer();
}

} // namespace

// Static window handle to bring window to foreground before Windows Hello
// dialogs
static HWND g_window_handle = nullptr;

// Helper function to bring the Flutter window to the foreground
static void BringWindowToForeground() {
  if (g_window_handle != nullptr) {
    SetForegroundWindow(g_window_handle);
    SetFocus(g_window_handle);
  }
}

// static
void BiometricSignaturePlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {

  // Get the Flutter window handle for bringing it to foreground before Windows
  // Hello dialogs
  flutter::FlutterView *view = registrar->GetView();
  if (view != nullptr) {
    g_window_handle = view->GetNativeWindow();
  }

  auto plugin = std::make_unique<BiometricSignaturePlugin>();

  // Set up the Pigeon API
  BiometricSignatureApi::SetUp(registrar->messenger(), plugin.get());

  registrar->AddPlugin(std::move(plugin));
}

BiometricSignaturePlugin::BiometricSignaturePlugin() {}

BiometricSignaturePlugin::~BiometricSignaturePlugin() {}

void BiometricSignaturePlugin::BiometricAuthAvailable(
    std::function<void(ErrorOr<BiometricAvailability> reply)> result) {

  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      IsSupportedAsync();

  async_op.Completed([result](auto const &op, auto status) {
    BiometricAvailability response;

    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      bool is_supported = op.GetResults();

      response.set_can_authenticate(is_supported);
      response.set_has_enrolled_biometrics(is_supported);

      flutter::EncodableList biometrics;
      if (is_supported) {
        biometrics.push_back(
            flutter::CustomEncodableValue(BiometricType::kFingerprint));
      }
      response.set_available_biometrics(biometrics);

      if (!is_supported) {
        response.set_reason("Windows Hello is not configured on this device");
      }
    } else {
      response.set_can_authenticate(false);
      response.set_has_enrolled_biometrics(false);
      response.set_available_biometrics(flutter::EncodableList());
      response.set_reason("Failed to check Windows Hello availability");
    }

    result(response);
  });
}

void BiometricSignaturePlugin::CreateKeys(
    const std::string *key_alias, const CreateKeysConfig *config,
    const KeyFormat &key_format, const std::string *prompt_message,
    std::function<void(ErrorOr<KeyCreationResult> reply)> result) {

  // Bring Flutter window to foreground so Windows Hello dialog appears properly
  BringWindowToForeground();

  std::wstring key_name = KeyNameForAlias(key_alias);
  std::wstring alias_marker = AliasMarkerFromOptionalAlias(key_alias);

  // Determine creation option based on failIfExists
  bool fail_if_exists = (config != nullptr && config->fail_if_exists() != nullptr && *config->fail_if_exists());

  auto creation_option = fail_if_exists
      ? winrt::Windows::Security::Credentials::KeyCredentialCreationOption::FailIfExists
      : winrt::Windows::Security::Credentials::KeyCredentialCreationOption::ReplaceExisting;

  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      RequestCreateAsync(key_name, creation_option);

  async_op.Completed([result, key_format, fail_if_exists, alias_marker](auto const &op, auto status) {
    KeyCreationResult response;

    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      auto create_result = op.GetResults();

      if (create_result.Status() ==
          winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {

        auto credential = create_result.Credential();
        auto public_key_buffer = credential.RetrievePublicKey();
        auto public_key_bytes = IBufferToVector(public_key_buffer);
        auto public_key_formatted =
            FormatPublicKey(public_key_bytes, key_format);

        response.set_public_key(public_key_formatted);
        response.set_public_key_bytes(public_key_bytes);
        response.set_algorithm("RSA");
        response.set_key_size(static_cast<int64_t>(2048));
        response.set_code(BiometricError::kSuccess);
        response.set_is_hybrid_mode(false);
        response.set_authentication_type(AuthenticationType::kUnknown);
        TrackAliasMarker(alias_marker);
      } else {
        std::string error_msg = "Failed to create key";
        BiometricError error_code = BiometricError::kUnknown;

        switch (create_result.Status()) {
        case winrt::Windows::Security::Credentials::KeyCredentialStatus::
            CredentialAlreadyExists:
          error_msg = "A key with the specified alias already exists";
          error_code = BiometricError::kKeyAlreadyExists;
          break;
        case winrt::Windows::Security::Credentials::KeyCredentialStatus::
            UserCanceled:
          error_msg = "User canceled the operation";
          error_code = BiometricError::kUserCanceled;
          break;
        case winrt::Windows::Security::Credentials::KeyCredentialStatus::
            NotFound:
          error_msg = "Windows Hello not found";
          error_code = BiometricError::kNotAvailable;
          break;
        case winrt::Windows::Security::Credentials::KeyCredentialStatus::
            SecurityDeviceLocked:
          error_msg = "Security device is locked";
          error_code = BiometricError::kLockedOut;
          break;
        default:
          break;
        }

        response.set_error(error_msg);
        response.set_code(error_code);
      }
    } else {
      response.set_error("Operation failed or was canceled");
      response.set_code(BiometricError::kUnknown);
    }

    result(response);
  });
}

void BiometricSignaturePlugin::CreateSignature(
    const std::string &payload, const std::string *key_alias,
    const CreateSignatureConfig *config,
    const SignatureFormat &signature_format, const KeyFormat &key_format,
    const std::string *prompt_message,
    std::function<void(ErrorOr<SignatureResult> reply)> result) {

  if (payload.empty()) {
    SignatureResult response;
    response.set_error("Payload is required");
    response.set_code(BiometricError::kInvalidInput);
    result(response);
    return;
  }

  // Bring Flutter window to foreground so Windows Hello dialog appears properly
  BringWindowToForeground();

  std::string payload_copy = payload;
  std::wstring key_name = KeyNameForAlias(key_alias);

  auto async_op =
      winrt::Windows::Security::Credentials::KeyCredentialManager::OpenAsync(
          key_name);

  async_op.Completed([result, payload_copy, key_format,
                      signature_format](auto const &op, auto status) {
    SignatureResult response;

    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      auto open_result = op.GetResults();

      if (open_result.Status() ==
          winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {

        auto credential = open_result.Credential();
        std::vector<uint8_t> payload_bytes(payload_copy.begin(),
                                           payload_copy.end());
        auto data_buffer = VectorToIBuffer(payload_bytes);

        auto sign_op = credential.RequestSignAsync(data_buffer);
        sign_op.Completed([result, credential, key_format, signature_format](
                              auto const &sign_async, auto sign_status) {
          SignatureResult resp;

          if (sign_status ==
              winrt::Windows::Foundation::AsyncStatus::Completed) {
            auto sign_result = sign_async.GetResults();

            if (sign_result.Status() == winrt::Windows::Security::Credentials::
                                            KeyCredentialStatus::Success) {

              auto signature_buffer = sign_result.Result();
              auto signature_bytes = IBufferToVector(signature_buffer);
              auto signature_formatted =
                  FormatSignature(signature_bytes, signature_format);

              auto public_key_buffer = credential.RetrievePublicKey();
              auto public_key_bytes = IBufferToVector(public_key_buffer);
              auto public_key_formatted =
                  FormatPublicKey(public_key_bytes, key_format);

              resp.set_signature(signature_formatted);
              resp.set_signature_bytes(signature_bytes);
              resp.set_public_key(public_key_formatted);
              resp.set_algorithm("RSA");
              resp.set_key_size(static_cast<int64_t>(2048));
              resp.set_code(BiometricError::kSuccess);
              resp.set_authentication_type(AuthenticationType::kUnknown);
            } else {
              std::string error_msg = "Signing failed";
              BiometricError error_code = BiometricError::kUnknown;

              switch (sign_result.Status()) {
              case winrt::Windows::Security::Credentials::KeyCredentialStatus::
                  UserCanceled:
                error_msg = "User canceled the operation";
                error_code = BiometricError::kUserCanceled;
                break;
              case winrt::Windows::Security::Credentials::KeyCredentialStatus::
                  SecurityDeviceLocked:
                error_msg = "Security device is locked";
                error_code = BiometricError::kLockedOut;
                break;
              default:
                break;
              }

              resp.set_error(error_msg);
              resp.set_code(error_code);
            }
          } else {
            resp.set_error("Signing operation failed");
            resp.set_code(BiometricError::kUnknown);
          }

          result(resp);
        });
        return; // Don't call result here, the nested callback will
      } else {
        response.set_error("Key not found. Please create keys first.");
        response.set_code(BiometricError::kKeyNotFound);
      }
    } else {
      response.set_error("Failed to open key");
      response.set_code(BiometricError::kUnknown);
    }

    result(response);
  });
}

void BiometricSignaturePlugin::DeleteKeys(
    const std::string *key_alias,
  std::function<void(ErrorOr<bool> reply)> result) {

  std::wstring key_name = KeyNameForAlias(key_alias);
  std::wstring alias_marker = AliasMarkerFromOptionalAlias(key_alias);

  auto async_op =
      winrt::Windows::Security::Credentials::KeyCredentialManager::DeleteAsync(
          key_name);

  async_op.Completed([result, alias_marker](auto const &op, auto status) {
    UntrackAliasMarker(alias_marker);
    result(true); // Return true even if key didn't exist
  });
}

// Helper: recursively delete keys one at a time, then call the completion.
static void DeleteKeysRecursive(
    std::shared_ptr<std::vector<std::wstring>> key_names,
    size_t index,
    std::function<void(ErrorOr<bool> reply)> result) {

  if (index >= key_names->size()) {
    // All keys deleted
    ClearTrackedAliasMarkers();
    result(true);
    return;
  }

  auto op = winrt::Windows::Security::Credentials::KeyCredentialManager::DeleteAsync(
          (*key_names)[index]);

  op.Completed([key_names, index, result](auto const& /*op*/, auto /*status*/) {
    DeleteKeysRecursive(key_names, index + 1, result);
  });
}

void BiometricSignaturePlugin::DeleteAllKeys(
    std::function<void(ErrorOr<bool> reply)> result) {

  auto key_names = std::make_shared<std::vector<std::wstring>>(TrackedKeyNames());

  if (key_names->empty()) {
    ClearTrackedAliasMarkers();
    result(true);
    return;
  }

  DeleteKeysRecursive(key_names, 0, result);
}

void BiometricSignaturePlugin::GetKeyInfo(
    const std::string *key_alias, bool check_validity,
    const KeyFormat &key_format,
    std::function<void(ErrorOr<KeyInfo> reply)> result) {

  std::wstring key_name = KeyNameForAlias(key_alias);

  auto async_op =
      winrt::Windows::Security::Credentials::KeyCredentialManager::OpenAsync(
          key_name);

  async_op.Completed([result, key_format, check_validity](auto const &op,
                                                          auto status) {
    KeyInfo response;

    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      auto open_result = op.GetResults();

      if (open_result.Status() ==
          winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {

        auto credential = open_result.Credential();
        auto public_key_buffer = credential.RetrievePublicKey();
        auto public_key_bytes = IBufferToVector(public_key_buffer);
        auto public_key_formatted =
            FormatPublicKey(public_key_bytes, key_format);

        response.set_exists(true);
        if (check_validity) {
          response.set_is_valid(true);
        }
        response.set_algorithm("RSA");
        response.set_key_size(static_cast<int64_t>(2048));
        response.set_is_hybrid_mode(false);
        response.set_public_key(public_key_formatted);
      } else {
        response.set_exists(false);
      }
    } else {
      response.set_exists(false);
    }

    result(response);
  });
}

void BiometricSignaturePlugin::Decrypt(
    const std::string &payload, const std::string *key_alias,
    const PayloadFormat &payload_format, const DecryptConfig *config,
    const std::string *prompt_message,
    std::function<void(ErrorOr<DecryptResult> reply)> result) {

  DecryptResult response;
  response.set_error(
      "Decryption is not supported on Windows. "
      "Windows Hello is designed for authentication and signing only.");
  response.set_code(BiometricError::kNotAvailable);
  result(response);
}

void BiometricSignaturePlugin::SimplePrompt(
    const std::string &prompt_message, const SimplePromptConfig *config,
    std::function<void(ErrorOr<SimplePromptResult> reply)> result) {

  // Bring Flutter window to foreground so Windows Hello dialog appears properly
  BringWindowToForeground();

  // First check if Windows Hello is available
  auto is_supported_op = winrt::Windows::Security::Credentials::
      KeyCredentialManager::IsSupportedAsync();

  is_supported_op.Completed([result, prompt_message](auto const &support_op,
                                                     auto support_status) {
    if (support_status != winrt::Windows::Foundation::AsyncStatus::Completed) {
      SimplePromptResult response;
      response.set_success(false);
      response.set_error("Failed to check Windows Hello availability");
      response.set_code(BiometricError::kUnknown);
      result(response);
      return;
    }

    bool is_supported = support_op.GetResults();
    if (!is_supported) {
      SimplePromptResult response;
      response.set_success(false);
      response.set_error("Windows Hello is not configured on this device");
      response.set_code(BiometricError::kNotAvailable);
      result(response);
      return;
    }

    // Use RequestSignAsync on the default key to trigger authentication
    auto open_op =
        winrt::Windows::Security::Credentials::KeyCredentialManager::OpenAsync(
            kDefaultKeyName);

    open_op.Completed([result, prompt_message](auto const &op, auto status) {
      if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
        auto open_result = op.GetResults();

        if (open_result.Status() == winrt::Windows::Security::Credentials::
                                        KeyCredentialStatus::Success) {
          auto credential = open_result.Credential();
          std::vector<uint8_t> dummy_data = {0x00};
          auto data_buffer = VectorToIBuffer(dummy_data);

          auto sign_op = credential.RequestSignAsync(data_buffer);
          sign_op.Completed([result](auto const &sign_async, auto sign_status) {
            SimplePromptResult resp;

            if (sign_status ==
                winrt::Windows::Foundation::AsyncStatus::Completed) {
              auto sign_result = sign_async.GetResults();

              if (sign_result.Status() ==
                  winrt::Windows::Security::Credentials::KeyCredentialStatus::
                      Success) {
                resp.set_success(true);
                resp.set_code(BiometricError::kSuccess);
                resp.set_authentication_type(AuthenticationType::kUnknown);
              } else {
                resp.set_success(false);
                BiometricError error_code = BiometricError::kUnknown;
                std::string error_msg = "Authentication failed";

                switch (sign_result.Status()) {
                case winrt::Windows::Security::Credentials::
                    KeyCredentialStatus::UserCanceled:
                  error_msg = "User canceled the operation";
                  error_code = BiometricError::kUserCanceled;
                  break;
                case winrt::Windows::Security::Credentials::
                    KeyCredentialStatus::SecurityDeviceLocked:
                  error_msg = "Security device is locked";
                  error_code = BiometricError::kLockedOut;
                  break;
                default:
                  break;
                }

                resp.set_error(error_msg);
                resp.set_code(error_code);
              }
            } else {
              resp.set_success(false);
              resp.set_error("Authentication operation failed");
              resp.set_code(BiometricError::kUnknown);
            }

            result(resp);
          });
          return;
        }
      }

      // No key exists - create a temporary key to trigger authentication
      auto create_op = winrt::Windows::Security::Credentials::
          KeyCredentialManager::RequestCreateAsync(
              L"BiometricSignatureTemp",
              winrt::Windows::Security::Credentials::
                  KeyCredentialCreationOption::ReplaceExisting);

      create_op.Completed([result](auto const &create_async,
                                   auto create_status) {
        SimplePromptResult resp;

        if (create_status ==
            winrt::Windows::Foundation::AsyncStatus::Completed) {
          auto create_result = create_async.GetResults();

          if (create_result.Status() == winrt::Windows::Security::Credentials::
                                            KeyCredentialStatus::Success) {
            winrt::Windows::Security::Credentials::KeyCredentialManager::
                DeleteAsync(L"BiometricSignatureTemp");

            resp.set_success(true);
            resp.set_code(BiometricError::kSuccess);
            resp.set_authentication_type(AuthenticationType::kUnknown);
          } else {
            resp.set_success(false);
            BiometricError error_code = BiometricError::kUnknown;
            std::string error_msg = "Authentication failed";

            switch (create_result.Status()) {
            case winrt::Windows::Security::Credentials::KeyCredentialStatus::
                UserCanceled:
              error_msg = "User canceled the operation";
              error_code = BiometricError::kUserCanceled;
              break;
            case winrt::Windows::Security::Credentials::KeyCredentialStatus::
                NotFound:
              error_msg = "Windows Hello not found";
              error_code = BiometricError::kNotAvailable;
              break;
            case winrt::Windows::Security::Credentials::KeyCredentialStatus::
                SecurityDeviceLocked:
              error_msg = "Security device is locked";
              error_code = BiometricError::kLockedOut;
              break;
            default:
              break;
            }

            resp.set_error(error_msg);
            resp.set_code(error_code);
          }
        } else {
          resp.set_success(false);
          resp.set_error("Authentication operation failed or was canceled");
          resp.set_code(BiometricError::kUnknown);
        }

        result(resp);
      });
    });
  });
}

void BiometricSignaturePlugin::IsDeviceLockSet(
    std::function<void(ErrorOr<bool> reply)> result) {
  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      IsSupportedAsync();

  async_op.Completed([result](auto const &op, auto status) {
    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      result(op.GetResults());
    } else {
      result(false);
    }
  });
}

} // namespace biometric_signature
