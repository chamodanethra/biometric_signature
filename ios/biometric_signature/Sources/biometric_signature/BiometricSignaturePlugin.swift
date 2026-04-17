#if os(macOS)
import FlutterMacOS
import Cocoa
#else
import Flutter
import UIKit
#endif
import LocalAuthentication
import Security

private enum Constants {
#if os(macOS)
    private static var appPrefix: String { Bundle.main.bundleIdentifier ?? "com.visionflutter.biometric_signature" }

    static func biometricKeyAlias(_ userAlias: String?) -> String {
        if let userAlias = userAlias {
            return "\(appPrefix).biometric_key_\(userAlias)"
        }
        return "\(appPrefix).biometric_key"
    }

    static func ecKeyAlias(_ userAlias: String?) -> Data {
        if let userAlias = userAlias {
            return "\(appPrefix).eckey_\(userAlias)".data(using: .utf8)!
        }
        return "\(appPrefix).eckey".data(using: .utf8)!
    }

    static func invalidationSettingKey(_ userAlias: String?) -> String {
        if let userAlias = userAlias {
            return "\(appPrefix).invalidation_setting_\(userAlias)"
        }
        return "\(appPrefix).invalidation_setting"
    }

    static let biometricKeyPrefix = "\(appPrefix).biometric_key"
    static let ecKeyPrefix = "\(appPrefix).eckey"
    static let invalidationSettingPrefix = "\(appPrefix).invalidation_setting"
#else
    static func biometricKeyAlias(_ userAlias: String?) -> String {
        if let userAlias = userAlias {
            return "biometric_key_\(userAlias)"
        }
        return "biometric_key"
    }

    static func ecKeyAlias(_ userAlias: String?) -> Data {
        if let userAlias = userAlias {
            return "com.visionflutter.eckey_\(userAlias)".data(using: .utf8)!
        }
        return "com.visionflutter.eckey".data(using: .utf8)!
    }

    static func invalidationSettingKey(_ userAlias: String?) -> String {
        if let userAlias = userAlias {
            return "com.visionflutter.biometric_signature.invalidation_setting_\(userAlias)"
        }
        return "com.visionflutter.biometric_signature.invalidation_setting"
    }

    static let biometricKeyPrefix = "biometric_key"
    static let ecKeyPrefix = "com.visionflutter.eckey"
    static let invalidationSettingPrefix = "com.visionflutter.biometric_signature.invalidation_setting"
#endif
}

// MARK: - Domain State (biometry change detection)
private enum DomainState {
    static let service = "com.visionflutter.biometric_signature.domain_state"
    private static func account(_ userAlias: String?) -> String {
        if let userAlias = userAlias {
            return "biometric_domain_state_v1_\(userAlias)"
        }
        return "biometric_domain_state_v1"
    }

    static func saveCurrent(_ userAlias: String?) {
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err),
              let state = ctx.evaluatedPolicyDomainState else { return }

        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(userAlias)
        ]
        let attrs: [String: Any] = [kSecValueData as String: state]
        let status = SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = base; add[kSecValueData as String] = state
            _ = SecItemAdd(add as CFDictionary, nil)
        }
    }

    static func loadSaved(_ userAlias: String?) -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(userAlias),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecSuccess, let d = out as? Data { return d }
        return nil
    }

    @discardableResult
    static func deleteSaved(_ userAlias: String?) -> Bool {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(userAlias)
        ]
        let s = SecItemDelete(q as CFDictionary)
        return s == errSecSuccess || s == errSecItemNotFound
    }

    /// Deletes all domain state entries for all aliases.
    @discardableResult
    static func deleteAll() -> Bool {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        let s = SecItemDelete(q as CFDictionary)
        return s == errSecSuccess || s == errSecItemNotFound
    }

    /// Returns true if biometry changed vs saved baseline (no UI).
    static func biometryChangedOrUnknown(_ userAlias: String?) -> Bool {
        let ctx = LAContext()
        var laErr: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laErr),
        let current = ctx.evaluatedPolicyDomainState else {
            // If we can't evaluate and we *had* a baseline, be conservative.
            return loadSaved(userAlias) != nil
        }
        if let saved = loadSaved(userAlias) { return saved != current }
        // First run / no baseline: save now and consider valid this time.
        saveCurrent(userAlias)
        return false
    }
}

// MARK: - Invalidation Setting Storage
private enum InvalidationSetting {
    static func save(_ invalidateOnEnrollment: Bool, userAlias: String?) {
        let key = Constants.invalidationSettingKey(userAlias)
        let data = invalidateOnEnrollment ? Data([1]) : Data([0])
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: key,
            kSecAttrAccount as String: key
        ]
        let attrs: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = base
            add[kSecValueData as String] = data
            _ = SecItemAdd(add as CFDictionary, nil)
        }
    }

    static func load(_ userAlias: String?) -> Bool? {
        let key = Constants.invalidationSettingKey(userAlias)
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: key,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecSuccess, let d = out as? Data, let first = d.first {
            return first == 1
        }
        return nil
    }

    @discardableResult
    static func delete(_ userAlias: String?) -> Bool {
        let key = Constants.invalidationSettingKey(userAlias)
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: key,
            kSecAttrAccount as String: key
        ]
        let s = SecItemDelete(q as CFDictionary)
        return s == errSecSuccess || s == errSecItemNotFound
    }
}

// MARK: - Device Credentials Setting Storage
//
// Apple's SecAccessControl is an opaque type: you can create one with flags
// (e.g. .userPresence, .biometryAny) but there is no public API to read those
// flags back. SecAccessControlGetConstraints exists in private headers but is
// not documented and would risk App Store rejection.
//
// Without being able to inspect the key's access control, we cannot tell at
// signing/decrypt time whether the key was created with .userPresence (which
// accepts passcode) or .biometryAny/.biometryCurrentSet (biometric only).
// We need this information to produce an accurate `authenticationType` in
// results, since iOS doesn't report which authentication method the user
// actually used after LAContext.evaluatePolicy succeeds.
//
// The workaround is to persist the `useDeviceCredentials` flag at key-creation
// time and read it back when signing or decrypting.
private enum DeviceCredentialsSetting {
    private static func service(_ keyAlias: String?) -> String {
        "com.visionflutter.biometric.deviceCredentials.\(keyAlias ?? "default")"
    }

    static func save(_ keyAlias: String?, allowsDeviceCredentials: Bool) {
        let service = service(keyAlias)
        let data = Data([allowsDeviceCredentials ? 1 : 0])
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: service,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let attrs: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = base
            add[kSecValueData as String] = data
            _ = SecItemAdd(add as CFDictionary, nil)
        }
    }

    static func read(_ keyAlias: String?) -> Bool? {
        let service = service(keyAlias)
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecSuccess, let d = out as? Data, let first = d.first {
            return first == 1
        }
        return nil
    }

    @discardableResult
    static func delete(_ keyAlias: String?) -> Bool {
        let service = service(keyAlias)
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: service
        ]
        let s = SecItemDelete(q as CFDictionary)
        return s == errSecSuccess || s == errSecItemNotFound
    }
}

public class BiometricSignaturePlugin: NSObject, FlutterPlugin, BiometricSignatureApi {

    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = BiometricSignaturePlugin()
#if os(macOS)
        BiometricSignatureApiSetup.setUp(binaryMessenger: registrar.messenger, api: instance)
#else
        BiometricSignatureApiSetup.setUp(binaryMessenger: registrar.messenger(), api: instance)
#endif
    }


    // MARK: - BiometricSignatureApi Implementation

    func biometricAuthAvailable(completion: @escaping (Result<BiometricAvailability, Error>) -> Void) {
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

        var availableBiometrics: [BiometricType?] = []
        if canEvaluate {
#if os(macOS)
             if #available(macOS 10.15, *) {
                 switch context.biometryType {
                 case .touchID: availableBiometrics.append(.fingerprint)
                 default: break
                 }
             }
#else
             if #available(iOS 11.0, *) {
                 switch context.biometryType {
                 case .faceID: availableBiometrics.append(.face)
                 case .touchID: availableBiometrics.append(.fingerprint)
                 default: break
                 }
             }
#endif
        }

        let hasEnrolled = error?.code != LAError.biometryNotEnrolled.rawValue

        completion(.success(BiometricAvailability(
            canAuthenticate: canEvaluate,
            hasEnrolledBiometrics: hasEnrolled,
            availableBiometrics: availableBiometrics,
            reason: error?.localizedDescription
        )))
    }

    func createKeys(
        keyAlias: String?,
        config: CreateKeysConfig?,
        keyFormat: KeyFormat,
        promptMessage: String?,
        completion: @escaping (Result<KeyCreationResult, Error>) -> Void
    ) {
        // Check failIfExists
        let failIfExists = config?.failIfExists ?? false
        if failIfExists && keyExists(keyAlias) {
            completion(.success(KeyCreationResult(
                publicKey: nil,
                error: "A key with alias '\(keyAlias ?? "default")' already exists",
                code: .keyAlreadyExists
            )))
            return
        }

        // Extract config values with defaults
        let useDeviceCredentials = config?.useDeviceCredentials ?? false
        let biometryCurrentSet = config?.setInvalidatedByBiometricEnrollment ?? false
        let signatureType = config?.signatureType ?? .rsa
        let enforceBiometric = config?.enforceBiometric ?? false
        let prompt = promptMessage ?? "Authenticate to create keys"

        // Delete existing keys for this alias first
        deleteExistingKeys(keyAlias)

        let authType: AuthenticationType? = enforceBiometric ? inferAuthenticationType(allowDeviceCredentials: useDeviceCredentials) : nil

        let generateBlock = {
            self.performKeyGeneration(
                keyAlias: keyAlias,
                useDeviceCredentials: useDeviceCredentials,
                biometryCurrentSet: biometryCurrentSet,
                signatureType: signatureType,
                keyFormat: keyFormat,
                authenticationType: authType
            ) { result in
                completion(result)
            }
        }

        if enforceBiometric {
            let context = LAContext()
            context.localizedFallbackTitle = ""
            context.localizedReason = prompt

            let policy: LAPolicy = useDeviceCredentials ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics
            context.evaluatePolicy(policy, localizedReason: prompt) { success, _ in
                if success {
                    generateBlock()
                } else {
                completion(.success(KeyCreationResult(publicKey: nil, error: "Authentication failed", code: .userCanceled)))
                }
            }
        } else {
             DispatchQueue.global(qos: .userInitiated).async {
                generateBlock()
            }
        }
    }

    func createSignature(
        payload: String,
        keyAlias: String?,
        config: CreateSignatureConfig?,
        signatureFormat: SignatureFormat,
        keyFormat: KeyFormat,
        promptMessage: String?,
        completion: @escaping (Result<SignatureResult, Error>) -> Void
    ) {
        guard let dataToSign = payload.data(using: .utf8) else {
             completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Invalid payload", code: .invalidInput)))
             return
        }

        let prompt = promptMessage ?? "Authenticate"
        let authType = inferAuthenticationType(allowDeviceCredentials: DeviceCredentialsSetting.read(keyAlias))

#if os(macOS)
        if hasRsaKey(keyAlias) {
             performRsaSigning(keyAlias: keyAlias, dataToSign: dataToSign, prompt: prompt, signatureFormat: signatureFormat, keyFormat: keyFormat, authenticationType: authType, completion: completion)
        } else {
             performEcSigning(keyAlias: keyAlias, dataToSign: dataToSign, prompt: prompt, signatureFormat: signatureFormat, keyFormat: keyFormat, authenticationType: authType, completion: completion)
        }
#else
        let shouldMigrate = config?.shouldMigrate ?? false
        if hasRsaKey(keyAlias) {
             performRsaSigning(keyAlias: keyAlias, dataToSign: dataToSign, prompt: prompt, signatureFormat: signatureFormat, keyFormat: keyFormat, authenticationType: authType, completion: completion)
        } else if shouldMigrate && keyAlias == nil {
             migrateToSecureEnclave(prompt: prompt) { result in
                switch result {
                case .success:
                    self.performRsaSigning(keyAlias: keyAlias, dataToSign: dataToSign, prompt: prompt, signatureFormat: signatureFormat, keyFormat: keyFormat, authenticationType: authType, completion: completion)
                case .failure(let error):
                     let msg = (error as? PigeonError)?.message ?? (error as NSError).localizedDescription
                     completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Migration Error: \(msg)", code: .unknown)))
                }
             }
        } else {
             performEcSigning(keyAlias: keyAlias, dataToSign: dataToSign, prompt: prompt, signatureFormat: signatureFormat, keyFormat: keyFormat, authenticationType: authType, completion: completion)
        }
#endif
    }

#if os(iOS)
    private func migrateToSecureEnclave(prompt: String, completion: @escaping (Result<Void, Error>) -> Void) {
        // Migration only operates on default alias
        let ecAccessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            nil
        )

        guard let ecAccessControl = ecAccessControl else {
            completion(.failure(PigeonError(code: "authFailed", message: "Failed to create access control for EC key", details: nil)))
            return
        }

        let ecTag = Constants.ecKeyAlias(nil)
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
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            completion(.failure(PigeonError(code: "authFailed", message: "Error generating EC key: \(msg)", details: nil)))
            return
        }

        guard let ecPublicKey = SecKeyCopyPublicKey(ecPrivateKey) else {
            completion(.failure(PigeonError(code: "authFailed", message: "Error getting EC public key", details: nil)))
            return
        }

        InvalidationSetting.save(false, userAlias: nil)

        let unencryptedKeyTag = Constants.biometricKeyAlias(nil)
        let unencryptedKeyTagData = unencryptedKeyTag.data(using: .utf8)!
        let unencryptedKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: unencryptedKeyTagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnData as String: true
        ]

        var rsaItem: CFTypeRef?
        let status = SecItemCopyMatching(unencryptedKeyQuery as CFDictionary, &rsaItem)
        guard status == errSecSuccess else {
            completion(.failure(PigeonError(code: "authFailed", message: "RSA private key not found in Keychain", details: nil)))
            return
        }
        guard var rsaPrivateKeyData = rsaItem as? Data else {
             completion(.failure(PigeonError(code: "authFailed", message: "Failed to retrieve RSA private key data", details: nil)))
            return
        }
        defer { rsaPrivateKeyData.resetBytes(in: 0..<rsaPrivateKeyData.count) }

        let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(ecPublicKey, .encrypt, algorithm) else {
            completion(.failure(PigeonError(code: "authFailed", message: "EC encryption algorithm not supported", details: nil)))
            return
        }

        guard let encryptedRSAKeyData = SecKeyCreateEncryptedData(ecPublicKey, algorithm, rsaPrivateKeyData as CFData, &error) as Data? else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            completion(.failure(PigeonError(code: "authFailed", message: "Error encrypting RSA private key: \(msg)", details: nil)))
            return
        }

        let encryptedKeyAttributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: unencryptedKeyTag,
            kSecAttrAccount as String: unencryptedKeyTag,
            kSecValueData as String: encryptedRSAKeyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        ]

        SecItemDelete(encryptedKeyAttributes as CFDictionary)
        let storeStatus = SecItemAdd(encryptedKeyAttributes as CFDictionary, nil)
        if storeStatus != errSecSuccess {
            completion(.failure(PigeonError(code: "authFailed", message: "Error storing encrypted RSA private key in Keychain", details: nil)))
            return
        }

        SecItemDelete(unencryptedKeyQuery as CFDictionary)

        completion(.success(()))
    }
#endif

    func decrypt(
        payload: String,
        keyAlias: String?,
        payloadFormat: PayloadFormat,
        config: DecryptConfig?,
        promptMessage: String?,
        completion: @escaping (Result<DecryptResult, Error>) -> Void
    ) {
        let prompt = promptMessage ?? "Authenticate"
        let authType = inferAuthenticationType(allowDeviceCredentials: DeviceCredentialsSetting.read(keyAlias))

#if os(macOS)
        if hasRsaKey(keyAlias) {
             performRsaDecryption(keyAlias: keyAlias, payload: payload, payloadFormat: payloadFormat, prompt: prompt, authenticationType: authType, completion: completion)
        } else {
             performEcDecryption(keyAlias: keyAlias, payload: payload, payloadFormat: payloadFormat, prompt: prompt, authenticationType: authType, completion: completion)
        }
#else
        let shouldMigrate = config?.shouldMigrate ?? false

        if hasRsaKey(keyAlias) {
             performRsaDecryption(keyAlias: keyAlias, payload: payload, payloadFormat: payloadFormat, prompt: prompt, authenticationType: authType, completion: completion)
        } else if shouldMigrate && keyAlias == nil {
             migrateToSecureEnclave(prompt: prompt) { result in
                switch result {
                case .success:
                     self.performRsaDecryption(keyAlias: keyAlias, payload: payload, payloadFormat: payloadFormat, prompt: prompt, authenticationType: authType, completion: completion)
                case .failure(let error):
                     let msg = (error as? PigeonError)?.message ?? (error as NSError).localizedDescription
                     completion(.success(DecryptResult(decryptedData: nil, error: "Migration Error: \(msg)", code: .unknown)))
                }
             }
        } else {
             performEcDecryption(keyAlias: keyAlias, payload: payload, payloadFormat: payloadFormat, prompt: prompt, authenticationType: authType, completion: completion)
        }
#endif
    }

    func deleteKeys(keyAlias: String?, completion: @escaping (Result<Bool, Error>) -> Void) {
        deleteExistingKeys(keyAlias)
        completion(.success(true))
    }

    func deleteAllKeys(completion: @escaping (Result<Bool, Error>) -> Void) {
        // Delete only plugin-owned EC and wrapped RSA records.
        deleteEcKeys(withTagPrefix: Constants.ecKeyPrefix)
        deleteGenericPasswords(withServicePrefix: Constants.biometricKeyPrefix)

        // Delete all plugin-owned domain state and invalidation settings.
        DomainState.deleteAll()
        deleteGenericPasswords(withServicePrefix: Constants.invalidationSettingPrefix)

        completion(.success(true))
    }

    func getKeyInfo(keyAlias: String?, checkValidity: Bool, keyFormat: KeyFormat, completion: @escaping (Result<KeyInfo, Error>) -> Void) {
        // Check EC key existence
        let ecTag = Constants.ecKeyAlias(keyAlias)
        let ecKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: ecTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var ecItem: CFTypeRef?
        let ecStatus = SecItemCopyMatching(ecKeyQuery as CFDictionary, &ecItem)
        let ecKeyExists = (ecStatus == errSecSuccess)
        let ecKey = ecItem as! SecKey?

        // Check if encrypted RSA key exists (hybrid mode)
        let encryptedKeyTag = Constants.biometricKeyAlias(keyAlias)
        let encryptedKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: encryptedKeyTag,
            kSecAttrAccount as String: encryptedKeyTag,
            kSecReturnData as String: true,
        ]
        var rsaItem: CFTypeRef?
        let rsaStatus = SecItemCopyMatching(encryptedKeyQuery as CFDictionary, &rsaItem)
        let rsaKeyExists = (rsaStatus == errSecSuccess)

        // No keys exist
        guard ecKeyExists else {
            completion(.success(KeyInfo(exists: false)))
            return
        }

        // Determine validity
        var isValid: Bool? = nil
        if checkValidity {
            let shouldInvalidateOnEnrollment = InvalidationSetting.load(keyAlias) ?? true
            if shouldInvalidateOnEnrollment {
                isValid = !DomainState.biometryChangedOrUnknown(keyAlias)
            } else {
                isValid = true
            }
        }

        // For EC-only mode
        if ecKeyExists && !rsaKeyExists {
            guard let ecPublicKey = ecKey.flatMap({ SecKeyCopyPublicKey($0) }) else {
                completion(.success(KeyInfo(exists: true, isValid: isValid, algorithm: "EC", keySize: 256, isHybridMode: false)))
                return
            }

            let publicKeyStr = formatKey(ecPublicKey, format: keyFormat)

            completion(.success(KeyInfo(
                exists: true,
                isValid: isValid,
                algorithm: "EC",
                keySize: 256,
                isHybridMode: false,
                publicKey: publicKeyStr,
                decryptingPublicKey: nil,
                decryptingAlgorithm: nil,
                decryptingKeySize: nil
            )))
            return
        }

        // Hybrid RSA mode
        completion(.success(KeyInfo(
            exists: true,
            isValid: isValid,
            algorithm: "RSA",
            keySize: 2048,
            isHybridMode: true,
            publicKey: nil,
            decryptingPublicKey: nil,
            decryptingAlgorithm: nil,
            decryptingKeySize: nil
        )))
    }

    func simplePrompt(
        promptMessage: String,
        config: SimplePromptConfig?,
        completion: @escaping (Result<SimplePromptResult, Error>) -> Void
    ) {
        let context = LAContext()

        let allowDeviceCredentials = config?.allowDeviceCredentials ?? false
        let policy: LAPolicy = allowDeviceCredentials
            ? .deviceOwnerAuthentication
            : .deviceOwnerAuthenticationWithBiometrics

        if !allowDeviceCredentials {
            context.localizedFallbackTitle = ""
        }

        var laError: NSError?
        guard context.canEvaluatePolicy(policy, error: &laError) else {
            let errorCode = mapLAError(laError)
            let errorMsg = laError?.localizedDescription ?? "Biometric authentication not available"
            completion(.success(SimplePromptResult(
                success: false,
                error: errorMsg,
                code: errorCode
            )))
            return
        }

        let authType = inferAuthenticationType(allowDeviceCredentials: allowDeviceCredentials)

        context.evaluatePolicy(policy, localizedReason: promptMessage) { success, error in
            DispatchQueue.main.async {
                if success {
                    completion(.success(SimplePromptResult(
                        success: true,
                        error: nil,
                        code: .success,
                        authenticationType: authType
                    )))
                } else {
                    let nsError = error as NSError?
                    let errorCode = self.mapLAError(nsError)
                    let errorMsg = error?.localizedDescription ?? "Authentication failed"
                    completion(.success(SimplePromptResult(
                        success: false,
                        error: errorMsg,
                        code: errorCode
                    )))
                }
            }
        }
    }

    func isDeviceLockSet(completion: @escaping (Result<Bool, Error>) -> Void) {
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        if canEvaluate {
            completion(.success(true))
        } else if let error = error, error.code == LAError.passcodeNotSet.rawValue {
            completion(.success(false))
        } else {
            // Policy can't be evaluated for other reasons (e.g. very old device),
            // but a passcode may still be set. Default to true to avoid false negatives.
            completion(.success(true))
        }
    }

    private func mapLAError(_ error: NSError?) -> BiometricError {
        guard let error = error else { return .unknown }

        switch Int32(error.code) {
        case kLAErrorUserCancel:
            return .userCanceled
        case kLAErrorSystemCancel:
            return .systemCanceled
        case kLAErrorUserFallback:
            return .userCanceled
        case kLAErrorBiometryNotAvailable:
            return .notAvailable
        case kLAErrorBiometryNotEnrolled:
            return .notEnrolled
        case kLAErrorBiometryLockout:
            return .lockedOut
        case kLAErrorAuthenticationFailed:
            return .unknown
        case kLAErrorPasscodeNotSet:
            return .passcodeNotSet
        case kLAErrorInvalidContext:
            return .promptError
        default:
            return .unknown
        }
    }

    private func mapSecError(_ status: OSStatus) -> BiometricError {
        switch status {
        case errSecUserCanceled, -128:
            return .userCanceled
        case errSecAuthFailed:
            return .unknown
        case errSecInteractionNotAllowed:
            return .notAvailable
        case -25300:
            return .keyNotFound
        default:
            if status < 0 && status > -100 {
                return mapLAError(NSError(domain: LAErrorDomain, code: Int(status), userInfo: nil))
            }
            return .unknown
        }
    }

    // MARK: - Private Implementations

    private func keyExists(_ keyAlias: String?) -> Bool {
        let ecTag = Constants.ecKeyAlias(keyAlias)
        let ecQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: ecTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: false
        ]
        var item: CFTypeRef?
        return SecItemCopyMatching(ecQuery as CFDictionary, &item) == errSecSuccess
    }

    private func performKeyGeneration(
        keyAlias: String?,
        useDeviceCredentials: Bool,
        biometryCurrentSet: Bool,
        signatureType: SignatureType,
        keyFormat: KeyFormat,
        authenticationType: AuthenticationType? = nil,
        completion: @escaping (Result<KeyCreationResult, Error>) -> Void
    ) {
        // Access Control
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage, useDeviceCredentials ? .userPresence : (biometryCurrentSet ? .biometryCurrentSet : .biometryAny)]
        guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, nil) else {
            completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "Failed to create access control", code: .unknown)))
            return
        }

        // Create EC Key
        let ecTag = Constants.ecKeyAlias(keyAlias)
        let ecAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessControl as String: accessControl,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: ecTag
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let ecPrivateKey = SecKeyCreateRandomKey(ecAttributes as CFDictionary, &error) else {
             let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "EC Key Gen Error: \(msg)", code: .unknown)))
             return
        }

        // Save metadata
        if biometryCurrentSet { DomainState.saveCurrent(keyAlias) }
        InvalidationSetting.save(biometryCurrentSet, userAlias: keyAlias)
        DeviceCredentialsSetting.save(keyAlias, allowsDeviceCredentials: useDeviceCredentials)

        guard let ecPublicKey = SecKeyCopyPublicKey(ecPrivateKey) else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "EC Pub Key Error", code: .unknown)))
             return
        }

        if signatureType == .ecdsa {
             let keyStr = formatKey(ecPublicKey, format: keyFormat)
             let data = SecKeyCopyExternalRepresentation(ecPublicKey, &error) as Data?
             let typedData = data != nil ? FlutterStandardTypedData(bytes: data!) : nil
             completion(.success(KeyCreationResult(
                 publicKey: keyStr,
                 publicKeyBytes: typedData,
                 error: nil,
                 code: .success,
                 algorithm: "EC",
                 keySize: 256,
                 decryptingPublicKey: nil,
                 decryptingAlgorithm: nil,
                 decryptingKeySize: nil,
                 isHybridMode: false,
                 authenticationType: authenticationType
             )))
             return
        }

        // Check encryption support for Hybrid
        guard SecKeyIsAlgorithmSupported(ecPublicKey, .encrypt, .eciesEncryptionStandardX963SHA256AESGCM) else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "ECIES not supported", code: .unknown)))
             return
        }

        // Generate RSA Key
        let rsaAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]
        ]
        guard let rsaPrivateKey = SecKeyCreateRandomKey(rsaAttributes as CFDictionary, &error) else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "RSA Gen Error", code: .unknown)))
             return
        }

        // Wrap RSA Private Key
        guard var rsaPrivateData = SecKeyCopyExternalRepresentation(rsaPrivateKey, &error) as Data? else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "RSA Wrapping Error", code: .unknown)))
             return
        }
        defer { rsaPrivateData.resetBytes(in: 0..<rsaPrivateData.count) }
        guard let encryptedRsa = SecKeyCreateEncryptedData(ecPublicKey, .eciesEncryptionStandardX963SHA256AESGCM, rsaPrivateData as CFData, &error) as Data? else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "RSA Wrapping Error", code: .unknown)))
             return
        }

        // Save Wrapped Key
        let tag = Constants.biometricKeyAlias(keyAlias)
        let saveQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecAttrAccount as String: tag,
            kSecValueData as String: encryptedRsa,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        ]
        SecItemAdd(saveQuery as CFDictionary, nil)

        guard let rsaPublicKey = SecKeyCopyPublicKey(rsaPrivateKey) else {
             completion(.success(KeyCreationResult(publicKey: nil, publicKeyBytes: nil, error: "RSA Pub Key Error", code: .unknown)))
             return
        }

        let rsaData = SecKeyCopyExternalRepresentation(rsaPublicKey, &error) as Data?
        let rsaTypedData = rsaData != nil ? FlutterStandardTypedData(bytes: rsaData!) : nil

        let rsaKeyStr = formatKey(rsaPublicKey, format: keyFormat)

        completion(.success(KeyCreationResult(
            publicKey: rsaKeyStr,
            publicKeyBytes: rsaTypedData,
            error: nil,
            code: .success,
            algorithm: "RSA",
            keySize: 2048,
            authenticationType: authenticationType
        )))
    }

    private func performRsaSigning(keyAlias: String?, dataToSign: Data, prompt: String, signatureFormat: SignatureFormat, keyFormat: KeyFormat, authenticationType: AuthenticationType, completion: @escaping (Result<SignatureResult, Error>) -> Void) {
        let keyResult = unwrapRsaKey(keyAlias: keyAlias, prompt: prompt)
        guard let rsaPrivateKey = keyResult.key else {
             completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Failed to access/unwrap RSA key", code: keyResult.error)))
             return
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(rsaPrivateKey, .rsaSignatureMessagePKCS1v15SHA256, dataToSign as CFData, &error) as Data? else {
             let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
             completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Signing Error: \(msg)", code: .unknown)))
             return
        }

        guard let pub = SecKeyCopyPublicKey(rsaPrivateKey) else {
             completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Pub Key Error", code: .unknown)))
             return
        }

        completion(.success(SignatureResult(
            signature: formatSignature(signature, format: signatureFormat),
            signatureBytes: FlutterStandardTypedData(bytes: signature),
            publicKey: formatKey(pub, format: keyFormat),
            error: nil,
            code: .success,
            algorithm: "RSA",
            keySize: 2048,
            authenticationType: authenticationType
        )))
    }

    private func performEcSigning(keyAlias: String?, dataToSign: Data, prompt: String, signatureFormat: SignatureFormat, keyFormat: KeyFormat, authenticationType: AuthenticationType, completion: @escaping (Result<SignatureResult, Error>) -> Void) {
        let keyResult = getEcPrivateKey(keyAlias: keyAlias, prompt: prompt)
        guard let ecKey = keyResult.key else {
             completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "EC Key not found or auth failed", code: keyResult.error)))
             return
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(ecKey, .ecdsaSignatureMessageX962SHA256, dataToSign as CFData, &error) as Data? else {
              let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
               completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Signing Error: \(msg)", code: .unknown)))
              return
        }
         guard let pub = SecKeyCopyPublicKey(ecKey) else {
              completion(.success(SignatureResult(signature: nil, signatureBytes: nil, publicKey: nil, error: "Pub Key Error", code: .unknown)))
             return
        }

        completion(.success(SignatureResult(
            signature: formatSignature(signature, format: signatureFormat),
            signatureBytes: FlutterStandardTypedData(bytes: signature),
            publicKey: formatKey(pub, format: keyFormat),
            error: nil,
            code: .success,
            algorithm: "EC",
            keySize: 256,
            authenticationType: authenticationType
        )))
    }

    private func performRsaDecryption(keyAlias: String?, payload: String, payloadFormat: PayloadFormat, prompt: String, authenticationType: AuthenticationType, completion: @escaping (Result<DecryptResult, Error>) -> Void) {
        let keyResult = unwrapRsaKey(keyAlias: keyAlias, prompt: prompt)
        guard let rsaPrivateKey = keyResult.key else {
               completion(.success(DecryptResult(decryptedData: nil, error: "Failed to access/unwrap RSA key", code: keyResult.error)))
               return
        }

        var error: Unmanaged<CFError>?
        guard let encryptedData = parsePayload(payload, format: payloadFormat) else {
             completion(.success(DecryptResult(decryptedData: nil, error: "Invalid payload", code: .invalidInput)))
             return
        }

        var oaepError: Unmanaged<CFError>?
        let decryptedData: Data
        if let oaepResult = SecKeyCreateDecryptedData(rsaPrivateKey, .rsaEncryptionOAEPSHA256, encryptedData as CFData, &oaepError) as Data? {
            decryptedData = oaepResult
        } else if let pkcs1Result = SecKeyCreateDecryptedData(rsaPrivateKey, .rsaEncryptionPKCS1, encryptedData as CFData, &error) as Data? {
            decryptedData = pkcs1Result
        } else {
            let msg = oaepError?.takeRetainedValue().localizedDescription
                ?? error?.takeRetainedValue().localizedDescription
                ?? "Unknown"
            completion(.success(DecryptResult(decryptedData: nil, error: "Decryption Error: \(msg)", code: .unknown)))
            return
        }

        guard let str = String(data: decryptedData, encoding: .utf8) else {
            completion(.success(DecryptResult(decryptedData: nil, error: "Decryption Error: Invalid UTF-8", code: .unknown)))
            return
        }

        completion(.success(DecryptResult(decryptedData: str, error: nil, code: .success, authenticationType: authenticationType)))
    }

    private func performEcDecryption(keyAlias: String?, payload: String, payloadFormat: PayloadFormat, prompt: String, authenticationType: AuthenticationType, completion: @escaping (Result<DecryptResult, Error>) -> Void) {
         let keyResult = getEcPrivateKey(keyAlias: keyAlias, prompt: prompt)
         guard let ecKey = keyResult.key else {
                completion(.success(DecryptResult(decryptedData: nil, error: "EC Key not found or auth failed", code: keyResult.error)))
               return
        }

        guard let encryptedData = parsePayload(payload, format: payloadFormat) else {
             completion(.success(DecryptResult(decryptedData: nil, error: "Invalid payload", code: .invalidInput)))
             return
        }

        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(ecKey, .eciesEncryptionStandardX963SHA256AESGCM, encryptedData as CFData, &error) as Data?,
              let str = String(data: decrypted, encoding: .utf8) else {
             let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown"
             completion(.success(DecryptResult(decryptedData: nil, error: "Decryption Error: \(msg)", code: .unknown)))
             return
        }
        completion(.success(DecryptResult(decryptedData: str, error: nil, code: .success, authenticationType: authenticationType)))
    }

    // MARK: - Helpers

    /// Best-effort inference of which authentication method was used.
    ///
    /// iOS/macOS do not report the actual method after `LAContext.evaluatePolicy`
    /// succeeds, so this is a pre-auth heuristic:
    ///  - If device credentials were not allowed for this key, only biometric
    ///    auth could have succeeded → `.biometric`.
    ///  - If device credentials were allowed and no biometric hardware exists,
    ///    only passcode could have succeeded → `.credential`.
    ///  - If the stored flag could not be read (e.g. keychain write failed) → `.unknown`.
    ///  - Otherwise we cannot tell → `.unknown`.
    ///
    /// `allowDeviceCredentials` should come from `DeviceCredentialsSetting` for
    /// key-based operations (sign/decrypt), or from the caller's config for
    /// `simplePrompt` (which has no stored key).
    private func inferAuthenticationType(allowDeviceCredentials: Bool?) -> AuthenticationType {
        guard let allowDeviceCredentials = allowDeviceCredentials else {
            return .unknown
        }
        if !allowDeviceCredentials {
            return .biometric
        }
        let context = LAContext()
        var error: NSError?
        let biometricsAvailable = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        if !biometricsAvailable {
            return .credential
        }
        return .unknown
    }

    private func deleteExistingKeys(_ keyAlias: String?) {
        let ecQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Constants.ecKeyAlias(keyAlias),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        SecItemDelete(ecQuery as CFDictionary)

        let rsaTag = Constants.biometricKeyAlias(keyAlias)
        let rsaQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: rsaTag,
            kSecAttrAccount as String: rsaTag
        ]
        SecItemDelete(rsaQuery as CFDictionary)

        _ = DomainState.deleteSaved(keyAlias)
        _ = InvalidationSetting.delete(keyAlias)
        _ = DeviceCredentialsSetting.delete(keyAlias)
    }


    private func deleteEcKeys(withTagPrefix prefix: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess,
              let attributes = items as? [[String: Any]] else {
            return
        }

        for item in attributes {
            guard let tagData = item[kSecAttrApplicationTag as String] as? Data,
                  let tag = String(data: tagData, encoding: .utf8),
                  tag.hasPrefix(prefix) else {
                continue
            }

            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tagData,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
            ]
            SecItemDelete(deleteQuery as CFDictionary)
        }
    }

    private func deleteGenericPasswords(withServicePrefix prefix: String, requireMatchingAccount: Bool) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess,
              let attributes = items as? [[String: Any]] else {
            return
        }

        for item in attributes {
            guard let service = item[kSecAttrService as String] as? String,
                  service.hasPrefix(prefix) else {
                continue
            }

            let account = item[kSecAttrAccount as String] as? String
            if requireMatchingAccount && account != service {
                continue
            }

            var deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service
            ]

            if let account {
                deleteQuery[kSecAttrAccount as String] = account
            }

            SecItemDelete(deleteQuery as CFDictionary)
        }
    }

    private func hasRsaKey(_ keyAlias: String?) -> Bool {
        let tag = Constants.biometricKeyAlias(keyAlias)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecAttrAccount as String: tag,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess
    }

    private func getEcPrivateKey(keyAlias: String?, prompt: String) -> (key: SecKey?, error: BiometricError) {
        let tag = Constants.ecKeyAlias(keyAlias)
        let context = LAContext()
        context.localizedReason = prompt

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess {
            return (item as! SecKey, .success)
        }
        return (nil, mapSecError(status))
    }

    private func unwrapRsaKey(keyAlias: String?, prompt: String) -> (key: SecKey?, error: BiometricError) {
        // 1. Get Wrapped Data
        let tag = Constants.biometricKeyAlias(keyAlias)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecAttrAccount as String: tag,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let fetchStatus = SecItemCopyMatching(query as CFDictionary, &item)
        guard fetchStatus == errSecSuccess, let wrappedData = item as? Data else {
            return (nil, mapSecError(fetchStatus))
        }

        // 2. Get EC Key (Auth logic handled by Secure Enclave)
        let ecKeyResult = getEcPrivateKey(keyAlias: keyAlias, prompt: prompt)
        guard let ecKey = ecKeyResult.key else {
            return (nil, ecKeyResult.error)
        }

        // 3. Unwrap
        var error: Unmanaged<CFError>?
        guard var rsaData = SecKeyCreateDecryptedData(ecKey, .eciesEncryptionStandardX963SHA256AESGCM, wrappedData as CFData, &error) as Data? else {
            if let cfError = error?.takeRetainedValue() {
                let nsError = cfError as Error as NSError
                if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? NSError,
                   underlying.domain == LAErrorDomain {
                    return (nil, mapLAError(underlying))
                }
            }
            return (nil, .unknown)
        }
        defer { rsaData.resetBytes(in: 0..<rsaData.count) }

        // 4. Restore Key
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048
        ]
        if let key = SecKeyCreateWithData(rsaData as CFData, attrs as CFDictionary, nil) {
            return (key, .success)
        }
        return (nil, .unknown)
    }

    private func formatKey(_ key: SecKey, format: KeyFormat) -> String {
        guard let data = subjectPublicKeyInfo(for: key) else { return "" }

        switch format {
        case .base64, .raw:
            return data.base64EncodedString()
        case .pem:
            let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            return "-----BEGIN PUBLIC KEY-----\n\(base64)\n-----END PUBLIC KEY-----"
        case .hex:
             return data.map { String(format: "%02x", $0) }.joined()
        }
    }

    private func subjectPublicKeyInfo(for key: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard let rawData = SecKeyCopyExternalRepresentation(key, &error) as Data? else { return nil }

        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              let keyType = attributes[kSecAttrKeyType as String] as? String else { return rawData }

        if keyType == (kSecAttrKeyTypeRSA as String) {
            let algorithmHeader: [UInt8] = [
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
            ]

            var bitString = Data()
            bitString.append(0x00)
            bitString.append(rawData)
            let bitStringEncoded = encodeASN1Content(tag: 0x03, content: bitString)

            var sequenceContent = Data(algorithmHeader)
            sequenceContent.append(bitStringEncoded)

            return encodeASN1Content(tag: 0x30, content: sequenceContent)

        } else if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            let algorithmHeader: [UInt8] = [
                0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
            ]

            var bitString = Data()
            bitString.append(0x00)
            bitString.append(rawData)
            let bitStringEncoded = encodeASN1Content(tag: 0x03, content: bitString)

            var sequenceContent = Data(algorithmHeader)
            sequenceContent.append(bitStringEncoded)
            return encodeASN1Content(tag: 0x30, content: sequenceContent)
        }

        return rawData
    }

    private func encodeASN1Content(tag: UInt8, content: Data) -> Data {
        var data = Data()
        data.append(tag)
        let length = content.count

        if length < 128 {
            data.append(UInt8(length))
        } else if length < 256 {
            data.append(0x81)
            data.append(UInt8(length))
        } else if length < 65536 {
            data.append(0x82)
            data.append(UInt8(length >> 8))
            data.append(UInt8(length & 0xFF))
        } else {
             data.append(0x83)
             data.append(UInt8(length >> 16))
             data.append(UInt8((length >> 8) & 0xFF))
             data.append(UInt8(length & 0xFF))
        }

        data.append(content)
        return data
    }

    private func formatSignature(_ data: Data, format: SignatureFormat) -> String {
        switch format {
        case .base64, .raw:
            return data.base64EncodedString()
        case .hex:
             return data.map { String(format: "%02x", $0) }.joined()
        }
    }

    private func parsePayload(_ payload: String, format: PayloadFormat) -> Data? {
        switch format {
        case .base64:
            return Data(base64Encoded: payload, options: .ignoreUnknownCharacters)
        case .hex:
            return parseHex(payload)
        case .raw:
            return Data(base64Encoded: payload, options: .ignoreUnknownCharacters)
        }
    }

    private func parseHex(_ hex: String) -> Data? {
        var data = Data()
        var hexStr = hex
         if hexStr.count % 2 != 0 { hexStr = "0" + hexStr }
         for i in stride(from: 0, to: hexStr.count, by: 2) {
             let start = hexStr.index(hexStr.startIndex, offsetBy: i)
             let end = hexStr.index(start, offsetBy: 2)
             guard let byte = UInt8(hexStr[start..<end], radix: 16) else { return nil }
             data.append(byte)
         }
         return data
    }
}
