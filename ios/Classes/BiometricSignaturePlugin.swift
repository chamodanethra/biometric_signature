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

// MARK: - Domain State (biometry change detection)
private enum DomainState {
    static let service = "com.visionflutter.biometric_signature.domain_state"

    private static func account() -> String { "biometric_domain_state_v1" }

    static func saveCurrent() {
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err),
              let state = ctx.evaluatedPolicyDomainState else { return }

        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account()
        ]
        let attrs: [String: Any] = [kSecValueData as String: state]
        let status = SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = base; add[kSecValueData as String] = state
            _ = SecItemAdd(add as CFDictionary, nil)
        }
    }

    static func loadSaved() -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecSuccess, let d = out as? Data { return d }
        return nil
    }

    @discardableResult
    static func deleteSaved() -> Bool {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account()
        ]
        let s = SecItemDelete(q as CFDictionary)
        return s == errSecSuccess || s == errSecItemNotFound
    }

    /// Returns true if biometry changed vs saved baseline (no UI).
    static func biometryChangedOrUnknown() -> Bool {
        let ctx = LAContext()
        var laErr: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laErr),
              let current = ctx.evaluatedPolicyDomainState else {
            // If we can't evaluate and we *had* a baseline, be conservative.
            return loadSaved() != nil
        }
        if let saved = loadSaved() { return saved != current }
        // First run / no baseline: save now and consider valid this time.
        saveCurrent()
        return false
    }
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
            createSignature(options: call.arguments as? [String: Any], result: result)
        case "deleteKeys":
            deleteKeys(result: result)
        case "biometricAuthAvailable":
            biometricAuthAvailable(result: result)
        case "biometricKeyExists":
            guard let checkValidity = call.arguments as? Bool else { return }
            biometricKeyExists(checkValidity: checkValidity, result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - Public API

    private func biometricAuthAvailable(result: @escaping FlutterResult) {
        let context = LAContext()
        var error: NSError?
        let canEvaluatePolicy = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

        if canEvaluatePolicy {
            let biometricType = getBiometricType(context)
            dispatchMainAsync { result(biometricType) }
        } else {
            let errorMessage = error?.localizedDescription ?? ""
            dispatchMainAsync { result("none, \(errorMessage)") }
        }
    }

    private func biometricKeyExists(checkValidity: Bool, result: @escaping FlutterResult) {
        let exists = self.doesBiometricKeyExist(checkValidity: checkValidity)
        dispatchMainAsync { result(exists) }
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

        // Delete saved domain-state baseline
        let dsOK = DomainState.deleteSaved()

        let success = (ecStatus == errSecSuccess || ecStatus == errSecItemNotFound)
                   && (rsaStatus == errSecSuccess || rsaStatus == errSecItemNotFound)
                   && dsOK
        dispatchMainAsync {
            if success {
                result(true)
            } else {
                result(FlutterError(code: Constants.authFailed, message: "Error deleting the biometric key", details: nil))
            }
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

        // Also delete the baseline to keep invariant: no baseline without keys
        _ = DomainState.deleteSaved()
    }

    private func createKeys(useDeviceCredentials: Bool, useEc: Bool, result: @escaping FlutterResult) {
        // Delete existing keys (and baseline)
        deleteExistingKeys()

        // Generate EC key pair in Secure Enclave
        // NOTE: If you want passcode fallback, consider using .userPresence
        // instead of .biometryAny.
        let ecAccessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, useDeviceCredentials ? .userPresence : .biometryAny],
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
                let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
                result(FlutterError(code: Constants.authFailed, message: "Error generating EC key: \(msg)", details: nil))
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

        // Persist domain-state baseline right after successful EC creation
        DomainState.saveCurrent()

        if useEc {
            // EC-only: return EC public key (X9.63 uncompressed + header)
            let publicKeyString = getPublicKeyString(ecPublicKey)
            dispatchMainAsync { result(publicKeyString) }
            return
        }

        // --- Hybrid path: generate RSA and wrap its private key with ECIES(X9.63/SHA-256/AES-GCM)
        let rsaKeyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]
        ]

        guard let rsaPrivate = SecKeyCreateRandomKey(rsaKeyAttributes as CFDictionary, &error),
              let rsaPublicKey = SecKeyCopyPublicKey(rsaPrivate) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error generating RSA key pair", details: nil))
            }
            return
        }

        // Extract RSA private key data
        guard let rsaPrivateKeyData = SecKeyCopyExternalRepresentation(rsaPrivate, &error) as Data? else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error extracting RSA private key data", details: nil))
            }
            return
        }

        // Encrypt RSA private key using EC public key
        let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(ecPublicKey, .encrypt, algorithm) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "EC encryption algorithm not supported", details: nil))
            }
            return
        }

        guard let encryptedRSAKeyData = SecKeyCreateEncryptedData(ecPublicKey, algorithm, rsaPrivateKeyData as CFData, &error) as Data? else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error encrypting RSA private key: \(msg)", details: nil))
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
        guard status == errSecSuccess else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error storing encrypted RSA private key in Keychain", details: nil))
            }
            return
        }

        // Get RSA public key data
        let publicKeyString = getPublicKeyString(rsaPublicKey)
        dispatchMainAsync { result(publicKeyString) }
    }

    private func createSignature(options: [String: Any]?, result: @escaping FlutterResult) {
        let promptMessage = (options?["promptMessage"] as? String) ?? "Authenticate"
        guard let payload = options?["payload"] as? String,
              let dataToSign = payload.data(using: .utf8) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.invalidPayload, message: "Payload is required and must be valid UTF-8", details: nil))
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
            let shouldMigrate = parseBool(options?["shouldMigrate"]) ?? false
            if shouldMigrate {
                self.migrateToSecureEnclave(options: options, result: result)
            } else {
                // No RSA: EC-only signing
                createECSignature(dataToSign: dataToSign, promptMessage: promptMessage, result: result)
            }
            return
        }

        // 1. Retrieve encrypted RSA private key from Keychain
        guard let encryptedRSAKeyData = item as? Data else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Failed to retrieve encrypted RSA key data", details: nil))
            }
            return
        }

        // 2. Retrieve EC private key from Secure Enclave
        let ecTag = Constants.ecKeyAlias

        let context = LAContext()
        context.localizedFallbackTitle = ""
        context.localizedReason = promptMessage

        let ecKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: ecTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecUseOperationPrompt as String: promptMessage
        ]

        var ecPrivateKeyRef: CFTypeRef?
        let ecStatus = SecItemCopyMatching(ecKeyQuery as CFDictionary, &ecPrivateKeyRef)
        guard ecStatus == errSecSuccess, let ecPrivateKeyRef = ecPrivateKeyRef else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "EC private key not found", details: nil))
            }
            return
        }
        let ecPrivateKey = ecPrivateKeyRef as! SecKey

        // 3. Decrypt RSA private key data using the EC private key
        let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(ecPrivateKey, .decrypt, algorithm) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "EC decryption algorithm not supported", details: nil))
            }
            return
        }

        var error: Unmanaged<CFError>?
        guard var rsaPrivateKeyData = SecKeyCreateDecryptedData(ecPrivateKey, algorithm, encryptedRSAKeyData as CFData, &error) as Data? else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error decrypting RSA private key: \(msg)", details: nil))
            }
            return
        }

        // 4. Reconstruct RSA private key from data
        let rsaKeyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048
        ]
        guard let rsaPrivateKey = SecKeyCreateWithData(rsaPrivateKeyData as CFData, rsaKeyAttributes as CFDictionary, &error) else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error reconstructing RSA private key: \(msg)", details: nil))
            }
            return
        }

        // 5. Sign data with RSA private key
        let signAlgorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(rsaPrivateKey, .sign, signAlgorithm) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "RSA signing algorithm not supported", details: nil))
            }
            return
        }

        guard let signature = SecKeyCreateSignature(rsaPrivateKey, signAlgorithm, dataToSign as CFData, &error) as Data? else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error signing data: \(msg)", details: nil))
            }
            return
        }

        // 6. Zero the decrypted RSA private key bytes in memory
        rsaPrivateKeyData.resetBytes(in: 0..<rsaPrivateKeyData.count)

        dispatchMainAsync { result(signature.base64EncodedString()) }
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
        guard ecStatus == errSecSuccess, let ecPrivateKeyRef = ecPrivateKeyRef else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "EC private key not found", details: nil))
            }
            return
        }
        let ecPrivateKey = ecPrivateKeyRef as! SecKey

        // Sign data with EC private key
        let signAlgorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(ecPrivateKey, .sign, signAlgorithm) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "EC signing algorithm not supported", details: nil))
            }
            return
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(ecPrivateKey, signAlgorithm, dataToSign as CFData, &error) as Data? else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error signing data with EC key: \(msg)", details: nil))
            }
            return
        }

        dispatchMainAsync { result(signature.base64EncodedString()) }
    }

    private func migrateToSecureEnclave(options: [String: Any]?, result: @escaping FlutterResult) {
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
                let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
                result(FlutterError(code: Constants.authFailed, message: "Error generating EC key: \(msg)", details: nil))
            }
            return
        }

        guard let ecPublicKey = SecKeyCopyPublicKey(ecPrivateKey) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error getting EC public key", details: nil))
            }
            return
        }

        // Save baseline after EC key creation
        DomainState.saveCurrent()

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
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            dispatchMainAsync {
                result(FlutterError(code: Constants.authFailed, message: "Error encrypting RSA private key: \(msg)", details: nil))
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
        modOptions?["shouldMigrate"] = false
        self.createSignature(options: modOptions, result: result)
        return
    }

    private func parseBool(_ value: Any?) -> Bool? {
        if let boolValue = value as? Bool {
            return boolValue
        }
        if let numberValue = value as? NSNumber {
            return numberValue.boolValue
        }
        if let stringValue = value as? String {
            return Bool(stringValue)
        }
        return nil
    }

    private func dispatchMainAsync(_ block: @escaping () -> Void) {
        DispatchQueue.main.async(execute: block)
    }

    private func getBiometricType(_ context: LAContext?) -> String {
        return context?.biometryType == .faceID ? "FaceID" :
               context?.biometryType == .touchID ? "TouchID" : "none, NO_BIOMETRICS"
    }

    private func doesBiometricKeyExist(checkValidity: Bool = false) -> Bool {
        // Check EC key existence
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
            guard checkValidity else { return true }
            // Non-interactive validity: return false if biometry changed
            return !DomainState.biometryChangedOrUnknown()
        }

        // Hybrid: both must exist
        guard ecKeyExists, rsaKeyExists else { return false }
        guard checkValidity else { return true }

        // Non-interactive validity for hybrid: domain-state compare
        return !DomainState.biometryChangedOrUnknown()
    }

    private func getBiometricKeyTag() -> Data {
        let BIOMETRIC_KEY_ALIAS = Constants.biometricKeyAlias
        let tag = BIOMETRIC_KEY_ALIAS.data(using: .utf8)
        return tag!
    }

    private static let encodedRSAEncryptionOID: [UInt8] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    ]

    private static let encodedECEncryptionOID: [UInt8] = [
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    ]

    private static func addHeader(publicKeyData: Data?, isEc: Bool = false) -> Data? {
        guard let publicKeyData = publicKeyData else { return nil }

    private static func addRSAHeader(publicKeyData: Data?) -> Data? {
        guard let publicKeyData = publicKeyData else { return nil }
        var builder = [UInt8](repeating: 0, count: 15)
        var encKey = Data()
        let bitLen: UInt = (publicKeyData.count + 1 < 128) ? 1 : UInt(((publicKeyData.count + 1) / 256) + 2)
        builder[0] = 0x30
        let i = encodedRSAEncryptionOID.count + 2 + Int(bitstringEncLength) + publicKeyData.count
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
