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
            if let arguments = call.arguments as? [String: Any] {
                let useDeviceCredentials = arguments["useDeviceCredentials"] as? Bool ?? false
                let useEc = arguments["useEc"] as? Bool ?? false
                createKeys(useDeviceCredentials: useDeviceCredentials, useEc: useEc, result: result)
            } else if let useDeviceCredentials = call.arguments as? Bool {
                // Backward compatibility
                createKeys(useDeviceCredentials: useDeviceCredentials, useEc: false, result: result)
            } else {
                result(FlutterError(code: Constants.invalidPayload, message: "Invalid arguments", details: nil))
            }
        case "createSignature":
            createSignature(options: call.arguments as? Dictionary<String, String>, result: result)
        case "deleteKeys":
            deleteKeys(result: result)
        case "biometricAuthAvailable":
            biometricAuthAvailable(result: result)
        case "biometricKeyExists":
            guard let checkValidity = call.arguments as? Bool else {
                return
            }
            biometricKeyExists(checkValidity: checkValidity, result: result)
        default:
            result(FlutterMethodNotImplemented)
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

    private func createKeys(useDeviceCredentials: Bool, useEc: Bool, result: @escaping FlutterResult) {
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

        if useEc {
            // EC-only mode: return the EC public key directly
            // Use SecKeyCopyExternalRepresentation with proper format
            let publicKeyString = getPublicKeyString(ecPublicKey)
            dispatchMainAsync {
                result(publicKeyString)
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
        let publicKeyString = getPublicKeyString(rsaPublicKey)
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

        // Check if we should use EC-only mode by checking if RSA key exists
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

        if status != errSecSuccess {
            // No RSA key found, try EC-only mode
            createECSignature(dataToSign: dataToSign, promptMessage: promptMessage, result: result)
            return
        }

        // 1. Retrieve encrypted RSA private key from Keychain
        guard let encryptedRSAKeyData = item as? Data else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Failed to retrieve encrypted RSA key data",
                                    details: nil))
            }
            return
        }

        // 2. Retrieve EC private key from Secure Enclave
        //    IMPORTANT: removed the direct LAContext usage
        //    and rely on iOS to prompt for authentication when
        //    we pass "kSecUseOperationPrompt".
        let ecTag = Constants.ecKeyAlias

        let ecKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: ecTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            // kSecUseAuthenticationContext as String: context,
            kSecUseOperationPrompt as String: promptMessage
        ]

    var ecPrivateKeyRef: CFTypeRef?
    let ecStatus = SecItemCopyMatching(ecKeyQuery as CFDictionary, &ecPrivateKeyRef)
    guard ecStatus == errSecSuccess else {
        dispatchMainAsync {
            result(FlutterError(code: Constants.authFailed, message: "EC private key not found", details: nil))
        }
        return
    }
    guard let ecPrivateKeyRef = ecPrivateKeyRef else {
        dispatchMainAsync {
            result(FlutterError(code: Constants.authFailed, message: "Failed to retrieve EC private key reference", details: nil))
        }
        return
    }
    let ecPrivateKey = ecPrivateKeyRef as! SecKey

        // 3. Decrypt RSA private key data using the EC private key
        let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(ecPrivateKey, .decrypt, algorithm) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "EC decryption algorithm not supported",
                                    details: nil))
            }
            return
        }

        var error: Unmanaged<CFError>?
        guard var rsaPrivateKeyData = SecKeyCreateDecryptedData(ecPrivateKey,
                                                                algorithm,
                                                                encryptedRSAKeyData as CFData,
                                                                &error) as Data?
        else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error decrypting RSA private key: \(errorDescription)",
                                    details: nil))
            }
            return
        }

        // 4. Reconstruct RSA private key from data
        let rsaKeyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048
        ]

        guard let rsaPrivateKey = SecKeyCreateWithData(rsaPrivateKeyData as CFData,
                                                       rsaKeyAttributes as CFDictionary,
                                                       &error)
        else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error reconstructing RSA private key: \(errorDescription)",
                                    details: nil))
            }
            return
        }

        // 5. Sign data with RSA private key
        let signAlgorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(rsaPrivateKey, .sign, signAlgorithm) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "RSA signing algorithm not supported",
                                    details: nil))
            }
            return
        }

        guard let signature = SecKeyCreateSignature(rsaPrivateKey,
                                                    signAlgorithm,
                                                    dataToSign as CFData,
                                                    &error) as Data?
        else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error signing data: \(errorDescription)",
                                    details: nil))
            }
            return
        }

        // 6. Zero out decrypted RSA private key data
        rsaPrivateKeyData.resetBytes(in: 0..<rsaPrivateKeyData.count)

        dispatchMainAsync {
            result(signature.base64EncodedString())
        }
    }

    private func createECSignature(dataToSign: Data, promptMessage: String, result: @escaping FlutterResult) {
        // Retrieve EC private key from Secure Enclave
        let ecTag = Constants.ecKeyAlias

        let ecKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: ecTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseOperationPrompt as String: promptMessage
        ]

        var ecPrivateKeyRef: CFTypeRef?
        let ecStatus = SecItemCopyMatching(ecKeyQuery as CFDictionary, &ecPrivateKeyRef)
        guard ecStatus == errSecSuccess else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "EC private key not found", details: nil))
            }
            return
        }
        guard let ecPrivateKeyRef = ecPrivateKeyRef else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Failed to retrieve EC private key reference", details: nil))
            }
            return
        }
        let ecPrivateKey = ecPrivateKeyRef as! SecKey

        // Sign data with EC private key
        let signAlgorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(ecPrivateKey, .sign, signAlgorithm) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "EC signing algorithm not supported",
                                    details: nil))
            }
            return
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(ecPrivateKey,
                                                    signAlgorithm,
                                                    dataToSign as CFData,
                                                    &error) as Data?
        else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed,
                                    message: "Error signing data with EC key: \(errorDescription)",
                                    details: nil))
            }
            return
        }

        dispatchMainAsync {
            result(signature.base64EncodedString())
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

        // For EC-only mode, only EC key needs to exist
        if ecKeyExists && !rsaKeyExists {
            if !checkValidity {
                return true
            }
            // Validate EC key by checking if it supports signing
            guard let ecItem = ecItem else {
                return false
            }
            let ecPrivateKey = ecItem as! SecKey
            return SecKeyIsAlgorithmSupported(ecPrivateKey, .sign, .ecdsaSignatureMessageX962SHA256)
        }

        // For hybrid mode, both keys must exist
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

    private func getPublicKeyString(_ publicKey: SecKey) -> String {
        var error: Unmanaged<CFError>?

        if let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? {
            // Check if it's an EC key by looking at the key size (EC keys are typically 65 bytes for secp256r1)
            let isEc = publicKeyData.count == 65

            if isEc {
                // Use the existing addHeader method for EC keys
                let publicKeyDataWithHeader = BiometricSignaturePlugin.addHeader(publicKeyData: publicKeyData, isEc: true)
                return publicKeyDataWithHeader?.base64EncodedString() ?? ""
            } else {
                // Use the existing addHeader method for RSA keys
                let publicKeyDataWithHeader = BiometricSignaturePlugin.addHeader(publicKeyData: publicKeyData, isEc: false)
                return publicKeyDataWithHeader?.base64EncodedString() ?? ""
            }
        }

        return ""
    }

    private static let encodedRSAEncryptionOID: [UInt8] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    ]

    private static let encodedECEncryptionOID: [UInt8] = [
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    ]

    private static func addHeader(publicKeyData: Data?, isEc: Bool = false) -> Data? {
        guard let publicKeyData = publicKeyData else { return nil }

        if isEc {
            return addECHeader(publicKeyData: publicKeyData)
        } else {
            return addRSAHeader(publicKeyData: publicKeyData)
        }
    }

    private static func addRSAHeader(publicKeyData: Data?) -> Data? {
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

    private static func addECHeader(publicKeyData: Data?) -> Data? {
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
        let i = encodedECEncryptionOID.count + 2 + Int(bitstringEncLength) + publicKeyData.count
        var j = encodedLength(&builder[1], i)
        encKey.append(&builder, count: Int(j + 1))
        encKey.append(encodedECEncryptionOID, count: encodedECEncryptionOID.count)
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
