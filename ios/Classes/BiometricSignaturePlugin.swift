import Flutter
import UIKit
import LocalAuthentication
import Security

private enum Constants {
    static let authFailed = "AUTH_FAILED"
    static let invalidPayload = "INVALID_PAYLOAD"
    static let biometricKeyAlias = "biometric_key"
    static let ecKeyAlias = "com.visionflutter.eckey".data(using: .utf8)!
}

public class BiometricSignaturePlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "biometric_signature", binaryMessenger: registrar.messenger())
        let instance = BiometricSignaturePlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "createKeys":
            createKeys(config: call.arguments as? [String: Any], result: result)
        case "createSignature":
            createSignature(options: call.arguments as? Dictionary<String, String>, result: result)
        case "deleteKeys":
            deleteKeys(result: result)
        case "biometricAuthAvailable":
            biometricAuthAvailable(result: result)
        case "biometricKeyExists":
            guard let checkValidity = call.arguments as? Bool else {
                result(FlutterError(code: "INVALID_ARGUMENTS", message: "Expected a boolean value", details: nil))
                return
            }
            biometricKeyExists(checkValidity: checkValidity, result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func promptBiometricAuth(
        reason: String,
        useDeviceCredentials: Bool = false,
        onSuccess: @escaping () -> Void,
        onError: @escaping (Error?) -> Void
    ) {
        let context = LAContext()
        var error: NSError?
        
        // Set up authentication policy based on preferences
        let policy: LAPolicy = useDeviceCredentials ? 
            .deviceOwnerAuthentication : // This allows passcode fallback
            .deviceOwnerAuthenticationWithBiometrics // Biometrics only
        
        // Check if the device can use biometric authentication
        guard context.canEvaluatePolicy(policy, error: &error) else {
            dispatchMainAsync {
                onError(error)
            }
            return
        }

        // Perform authentication
        context.evaluatePolicy(
            policy,
            localizedReason: reason
        ) { success, error in
            if success {
                self.dispatchMainAsync {
                    onSuccess()
                }
            } else {
                self.dispatchMainAsync {
                    onError(error)
                }
            }
        }
    }

    private func biometricAuthAvailable(result: @escaping FlutterResult) {
        let context = LAContext()
        var error: NSError?
        let canEvaluatePolicy = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

        if canEvaluatePolicy {
            let biometricType = getBiometricType(context)
            dispatchMainAsync {
                result(biometricType)
            }
        } else {
            let errorMessage = error?.localizedDescription ?? ""
            dispatchMainAsync {
                result("none, \(errorMessage)")
            }
        }
    }

    private func biometricKeyExists(checkValidity: Bool, result: @escaping FlutterResult) {
        let biometricKeyExists = self.doesBiometricKeyExist(checkValidity: checkValidity)
        dispatchMainAsync {
            result(biometricKeyExists)
        }
    }

    private func deleteKeys(result: @escaping FlutterResult) {
        // Delete EC key pair
        let ecTag = Constants.ecKeyAlias
        let ecKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: ecTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let ecStatus = SecItemDelete(ecKeyQuery as CFDictionary)

        // Delete encrypted RSA private key from Keychain
        let encryptedKeyTag = getBiometricKeyTag()
        let encryptedKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: encryptedKeyTag,
            kSecAttrAccount as String: encryptedKeyTag
        ]
        let rsaStatus = SecItemDelete(encryptedKeyQuery as CFDictionary)

        let success = (ecStatus == errSecSuccess || ecStatus == errSecItemNotFound) &&
                      (rsaStatus == errSecSuccess || rsaStatus == errSecItemNotFound)
        dispatchMainAsync {
            result(success)
        }
    }

    private func deleteExistingKeys() {
        // Delete EC key pair
        let ecTag = Constants.ecKeyAlias
        let ecKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: ecTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        SecItemDelete(ecKeyQuery as CFDictionary)

        // Delete encrypted RSA private key from Keychain
        let encryptedKeyTag = getBiometricKeyTag()
        let encryptedKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: encryptedKeyTag,
            kSecAttrAccount as String: encryptedKeyTag
        ]
        SecItemDelete(encryptedKeyQuery as CFDictionary)
    }

    private func createKeys(config: [String: Any]?, result: @escaping FlutterResult) {
        let useDeviceCredentials = config?["useDeviceCredentials"] as? Bool ?? false
        let enforceBiometric = config?["enforceBiometric"] as? Bool ?? false

        let options = config?["options"] as? [String: Any] ?? [:]
        let promptMessage = options["promptMessage"] as? String ?? "Authenticate"
        
        if enforceBiometric {
            promptBiometricAuth(
                reason: promptMessage,
                useDeviceCredentials: useDeviceCredentials,
                onSuccess: {
                    self.proceedWithKeyGeneration(useDeviceCredentials: useDeviceCredentials, result: result)
                },
                onError: { error in
                    self.dispatchMainAsync {
                        result(FlutterError(code: Constants.authFailed,
                                          message: "Biometric authentication failed: \(error?.localizedDescription ?? "User cancelled")",
                                          details: nil))
                    }
                }
            )
        } else {
            proceedWithKeyGeneration(useDeviceCredentials: useDeviceCredentials, result: result)
        }
    }

    private func proceedWithKeyGeneration(useDeviceCredentials: Bool, result: @escaping FlutterResult) {
        // Delete existing keys
        deleteExistingKeys()

        // Generate EC key pair in Secure Enclave
        // NOTE: If you want passcode fallback, consider using .userPresence
        // instead of .biometryAny.
        let ecAccessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, useDeviceCredentials ? .userPresence: .biometryAny],
            nil
        )

        guard let ecAccessControl = ecAccessControl else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Failed to create access control for EC key",
                                    details: nil))
            }
            return
        }

        let ecTag = Constants.ecKeyAlias

        let ecKeyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessControl as String: ecAccessControl,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: ecTag
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let ecPrivateKey = SecKeyCreateRandomKey(ecKeyAttributes as CFDictionary, &error) else {
            dispatchMainAsync {
                let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error generating EC key: \(errorDescription)",
                                    details: nil))
            }
            return
        }

        guard let ecPublicKey = SecKeyCopyPublicKey(ecPrivateKey) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error getting EC public key",
                                    details: nil))
            }
            return
        }

        // Generate RSA key pair
        let rsaKeyAttributes: [String: Any] = ([
            kSecAttrKeyType as AnyHashable: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as AnyHashable: NSNumber(value: 2048),
            kSecPrivateKeyAttrs as AnyHashable: [
                kSecAttrIsPermanent as AnyHashable: NSNumber(value: false),
            ] as Any
        ] as CFDictionary) as! [String : Any]

        var rsaPrivateKey: SecKey?
        rsaPrivateKey = SecKeyCreateRandomKey(rsaKeyAttributes as CFDictionary, &error)

        guard let rsaPrivate = rsaPrivateKey,
              let rsaPublicKey = SecKeyCopyPublicKey(rsaPrivate)
        else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error generating RSA key pair",
                                    details: nil))
            }
            return
        }

        // Extract RSA private key data
        guard let rsaPrivateKeyData = SecKeyCopyExternalRepresentation(rsaPrivate, &error) as Data? else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error extracting RSA private key data",
                                    details: nil))
            }
            return
        }

        // Encrypt RSA private key using EC public key
        let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(ecPublicKey, .encrypt, algorithm) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "EC encryption algorithm not supported",
                                    details: nil))
            }
            return
        }

        guard let encryptedRSAKeyData = SecKeyCreateEncryptedData(ecPublicKey,
                                                                  algorithm,
                                                                  rsaPrivateKeyData as CFData,
                                                                  &error) as Data?
        else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error encrypting RSA private key: \(errorDescription)",
                                    details: nil))
            }
            return
        }

        // Store encrypted RSA private key data in Keychain
        let encryptedKeyTag = getBiometricKeyTag()
        let encryptedKeyAttributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: encryptedKeyTag,
            kSecAttrAccount as String: encryptedKeyTag,
            kSecValueData as String: encryptedRSAKeyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        SecItemDelete(encryptedKeyAttributes as CFDictionary) // Delete existing item
        let status = SecItemAdd(encryptedKeyAttributes as CFDictionary, nil)
        if status != errSecSuccess {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error storing encrypted RSA private key in Keychain",
                                    details: nil))
            }
            return
        }

        // Get RSA public key data
        guard let rsaPublicKeyData = SecKeyCopyExternalRepresentation(rsaPublicKey, &error) as Data? else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error extracting RSA public key data",
                                    details: nil))
            }
            return
        }

        // Add header to public key data
        let publicKeyDataWithHeader = BiometricSignaturePlugin.addHeader(publicKeyData: rsaPublicKeyData)
        let publicKeyString = publicKeyDataWithHeader?.base64EncodedString() ?? ""
        dispatchMainAsync {
            result(publicKeyString)
        }
    }

    private func createSignature(options: [String: String]?, result: @escaping FlutterResult) {
        let promptMessage = options?["promptMessage"] ?? "Authenticate to sign data"
        guard let payload = options?["payload"],
            let dataToSign = payload.data(using: .utf8) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.invalidPayload,
                                    message: "Payload is required and must be valid UTF-8",
                                    details: nil))
            }
            return
        }

        // 1. Retrieve encrypted RSA private key from Keychain
        let encryptedKeyTag = getBiometricKeyTag()
        let encryptedKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: encryptedKeyTag,
            kSecAttrAccount as String: encryptedKeyTag,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(encryptedKeyQuery as CFDictionary, &item)
        guard status == errSecSuccess else {
            let shouldMigrate = options?["shouldMigrate"] ?? "false"
            if Bool(shouldMigrate) == true {
                self.migrateToSecureEnclave(options: options, result: result)
            } else {
                dispatchMainAsync {
                    result(FlutterError(code: Constants.authFailed,
                                        message: "Encrypted RSA key not found in Keychain",
                                        details: nil))
                }
            }
            return
        }
        guard let encryptedRSAKeyData = item as? Data else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Failed to retrieve encrypted RSA key data",
                                    details: nil))
            }
            return
        }

        // 2. Set up for authentication to decrypt RSA key
        let useDeviceCredentials = options?["allowDeviceCredentials"]?.lowercased() == "true"
        let ecTag = Constants.ecKeyAlias
        
        // Create a context for authentication
        let context = LAContext()
        var error: NSError?
        
        // Set up authentication policy based on preferences
        let policy: LAPolicy = useDeviceCredentials ? 
            .deviceOwnerAuthentication : // This allows passcode fallback
            .deviceOwnerAuthenticationWithBiometrics // Biometrics only
        
        // Check if authentication is available
        guard context.canEvaluatePolicy(policy, error: &error) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, 
                                message: "Biometric authentication not available: \(error?.localizedDescription ?? "Unknown error")",
                                details: nil))
            }
            return
        }
        
        // 3. Use the LAContext to evaluate policy
        context.evaluatePolicy(policy, localizedReason: promptMessage) { success, error in
            if !success {
                self.dispatchMainAsync {
                    result(FlutterError(code: Constants.authFailed,
                                    message: "Authentication failed: \(error?.localizedDescription ?? "User cancelled")",
                                    details: nil))
                }
                return
            }
            
            // 4. After successful authentication, retrieve EC key with context
            let ecKeyQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: ecTag,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef as String: true,
                kSecUseAuthenticationContext as String: context  // Use the same authentication context
            ]
            
            var ecPrivateKeyRef: CFTypeRef?
            let ecStatus = SecItemCopyMatching(ecKeyQuery as CFDictionary, &ecPrivateKeyRef)
            
            guard ecStatus == errSecSuccess, let ecPrivateKeyRef = ecPrivateKeyRef else {
                self.dispatchMainAsync {
                    result(FlutterError(code: Constants.authFailed, 
                                    message: "EC private key not found after authentication", 
                                    details: nil))
                }
                return
            }
            
            // 5. Now proceed with decryption and signing
            let ecPrivateKey = ecPrivateKeyRef as! SecKey
            
            // Decrypt RSA private key data using the EC private key
            let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
            guard SecKeyIsAlgorithmSupported(ecPrivateKey, .decrypt, algorithm) else {
                self.dispatchMainAsync {
                    result(FlutterError(code: Constants.authFailed,
                                        message: "EC decryption algorithm not supported",
                                        details: nil))
                }
                return
            }

            var cfError: Unmanaged<CFError>?
            guard var rsaPrivateKeyData = SecKeyCreateDecryptedData(ecPrivateKey,
                                                                    algorithm,
                                                                    encryptedRSAKeyData as CFData,
                                                                    &cfError) as Data?
            else {
                let errorDescription = cfError?.takeRetainedValue().localizedDescription ?? "Unknown error"
                self.dispatchMainAsync {
                    result(FlutterError(code: Constants.authFailed,
                                        message: "Error decrypting RSA private key: \(errorDescription)",
                                        details: nil))
                }
                return
            }

            // Reconstruct RSA private key from data
            let rsaKeyAttributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: 2048
            ]

            guard let rsaPrivateKey = SecKeyCreateWithData(rsaPrivateKeyData as CFData,
                                                        rsaKeyAttributes as CFDictionary,
                                                        &cfError)
            else {
                let errorDescription = cfError?.takeRetainedValue().localizedDescription ?? "Unknown error"
                self.dispatchMainAsync {
                    result(FlutterError(code: Constants.authFailed,
                                        message: "Error reconstructing RSA private key: \(errorDescription)",
                                        details: nil))
                }
                return
            }

            // Sign data with RSA private key
            let signAlgorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
            guard SecKeyIsAlgorithmSupported(rsaPrivateKey, .sign, signAlgorithm) else {
                self.dispatchMainAsync {
                    result(FlutterError(code: Constants.authFailed,
                                        message: "RSA signing algorithm not supported",
                                        details: nil))
                }
                return
            }

            guard let signature = SecKeyCreateSignature(rsaPrivateKey,
                                                        signAlgorithm,
                                                        dataToSign as CFData,
                                                        &cfError) as Data?
            else {
                let errorDescription = cfError?.takeRetainedValue().localizedDescription ?? "Unknown error"
                self.dispatchMainAsync {
                    result(FlutterError(code: Constants.authFailed,
                                        message: "Error signing data: \(errorDescription)",
                                        details: nil))
                }
                return
            }

            // Zero out decrypted RSA private key data
            rsaPrivateKeyData.resetBytes(in: 0..<rsaPrivateKeyData.count)

            self.dispatchMainAsync {
                result(signature.base64EncodedString())
            }
        }
    }

    private func migrateToSecureEnclave(options: [String: String]?, result: @escaping FlutterResult) {
        // Generate EC key pair in Secure Enclave
        let ecAccessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            nil
        )

        guard let ecAccessControl = ecAccessControl else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Failed to create access control for EC key", details: nil))
            }
            return
        }

        let ecTag = Constants.ecKeyAlias

        let ecKeyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessControl as String: ecAccessControl,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: ecTag
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let ecPrivateKey = SecKeyCreateRandomKey(ecKeyAttributes as CFDictionary, &error) else {
            dispatchMainAsync {
                let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
                result(FlutterError(code: Constants.authFailed, message: "Error generating EC key: \(errorDescription)", details: nil))
            }
            return
        }

        guard let ecPublicKey = SecKeyCopyPublicKey(ecPrivateKey) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error getting EC public key", details: nil))
            }
            return
        }

        let unencryptedKeyTag = getBiometricKeyTag()
        let unencryptedKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: unencryptedKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnData as String: true
        ]

        var rsaItem: CFTypeRef?
        let status = SecItemCopyMatching(unencryptedKeyQuery as CFDictionary, &rsaItem)
        guard status == errSecSuccess else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "RSA private key not found in Keychain", details: nil))
            }
            return
        }
        guard var rsaPrivateKeyData = rsaItem as? Data else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Failed to retrieve RSA private key data", details: nil))
            }
            return
        }

        let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(ecPublicKey, .encrypt, algorithm) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "EC encryption algorithm not supported", details: nil))
            }
            return
        }

        guard let encryptedRSAKeyData = SecKeyCreateEncryptedData(ecPublicKey, algorithm, rsaPrivateKeyData as CFData, &error) as Data? else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error encrypting RSA private key: \(errorDescription)", details: nil))
            }
            return
        }

        let encryptedKeyAttributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: unencryptedKeyTag,
            kSecAttrAccount as String: unencryptedKeyTag,
            kSecValueData as String: encryptedRSAKeyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        SecItemDelete(encryptedKeyAttributes as CFDictionary) // Delete any existing item
        let storeStatus = SecItemAdd(encryptedKeyAttributes as CFDictionary, nil)
        if storeStatus != errSecSuccess {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error storing encrypted RSA private key in Keychain", details: nil))
            }
            return
        }

        SecItemDelete(unencryptedKeyQuery as CFDictionary)
        rsaPrivateKeyData.resetBytes(in: 0..<rsaPrivateKeyData.count)

        var modOptions = options
        modOptions?["shouldMigrate"] = "false"
        self.createSignature(options: modOptions, result: result)
        return
    }

    private func dispatchMainAsync(_ block: @escaping () -> Void) {
        DispatchQueue.main.async(execute: block)
    }

    private func getBiometricType(_ context: LAContext?) -> String {
        if context?.biometryType == .faceID {
            return "FaceID"
        } else if context?.biometryType == .touchID {
            return "TouchID"
        }
        return "none, NO_BIOMETRICS"
    }

    private func doesBiometricKeyExist(checkValidity: Bool = false) -> Bool {
        let ecTag = Constants.ecKeyAlias
        let ecKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: ecTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var ecItem: CFTypeRef?
        let ecStatus = SecItemCopyMatching(ecKeyQuery as CFDictionary, &ecItem)
        let ecKeyExists = (ecStatus == errSecSuccess)

        // Check if encrypted RSA key exists
        let encryptedKeyTag = getBiometricKeyTag()
        let encryptedKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: encryptedKeyTag,
            kSecAttrAccount as String: encryptedKeyTag,
            kSecReturnData as String: true,
        ]
        var rsaItem: CFTypeRef?
        let rsaStatus = SecItemCopyMatching(encryptedKeyQuery as CFDictionary, &rsaItem)
        let rsaKeyExists = (rsaStatus == errSecSuccess)

        if !ecKeyExists || !rsaKeyExists {
            return false
        }

        if !checkValidity {
            return true
        }

        // Validate the EC key by attempting to decrypt the RSA key
        guard let ecItem = ecItem else {
            return false
        }
        let ecPrivateKey = ecItem as! SecKey

        let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(ecPrivateKey, .decrypt, algorithm) else {
            return false
        }

        guard rsaItem is Data else {
            return false
        }
        return true
    }

    private func getBiometricKeyTag() -> Data {
        let BIOMETRIC_KEY_ALIAS = Constants.biometricKeyAlias
        let tag = BIOMETRIC_KEY_ALIAS.data(using: .utf8)
        return tag!
    }

    private static let encodedRSAEncryptionOID: [UInt8] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    ]

    private static func addHeader(publicKeyData: Data?) -> Data? {
        guard let publicKeyData = publicKeyData else { return nil }

        var builder = [UInt8](repeating: 0, count: 15)
        var encKey = Data()
        let bitstringEncLength: UInt
        if publicKeyData.count + 1 < 128 {
            bitstringEncLength = 1
        } else {
            bitstringEncLength = UInt(((publicKeyData.count + 1) / 256) + 2)
        }
        builder[0] = 0x30
        let i = encodedRSAEncryptionOID.count + 2 + Int(bitstringEncLength) + publicKeyData.count
        var j = encodedLength(&builder[1], i)
        encKey.append(&builder, count: Int(j + 1))
        encKey.append(encodedRSAEncryptionOID, count: encodedRSAEncryptionOID.count)
        builder[0] = 0x03
        j = encodedLength(&builder[1], publicKeyData.count + 1)
        builder[j + 1] = 0x00
        encKey.append(&builder, count: Int(j + 2))
        encKey.append(publicKeyData)
        return encKey
    }

    private static func encodedLength(_ buf: UnsafeMutablePointer<UInt8>?,
                                      _ length: size_t) -> size_t {
        var length = length
        if length < 128 {
            buf?[0] = UInt8(length)
            return 1
        }
        let i: size_t = (length / 256) + 1
        buf?[0] = UInt8(i + 0x80)
        for j in 0..<i {
            buf?[i - j] = UInt8(length & 0xff)
            length >>= 8
        }
        return i + 1
    }
}
