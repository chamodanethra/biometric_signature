import Flutter
import UIKit
import LocalAuthentication
import Security

private enum Constants {
    static let authFailed = "AUTHFAILED"
    static let invalidPayload = "INVALID_PAYLOAD"
    static let userCancel = "USERCANCEL"
    static let biometricKeyAlias = "biometric_key"
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
            createKeys(result: result)
        case "createSignature":
            self.createSignature(options: call.arguments as? Dictionary<String, String>, result: result)
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
            result(biometricType)
        } else {
            let errorMessage = error?.localizedDescription ?? ""
            result("none, \(errorMessage)")
        }
    }
    
    private func biometricKeyExists(checkValidity: Bool, result: @escaping FlutterResult) {
        let biometricKeyExists = self.doesBiometricKeyExist(checkValidity: checkValidity)
        result(biometricKeyExists)
    }
    
    private func deleteKeys(result: @escaping FlutterResult) {
        let biometricKeyExists = self.doesBiometricKeyExist()
        if biometricKeyExists {
            let status = self.deleteBiometricKey()
            result(status == noErr)
        } else {
            result(false)
        }
    }
    
    private func createKeys(result: @escaping FlutterResult) {
        let tag = self.getBiometricKeyTag()
        var secObject: SecAccessControl?
        var error: Unmanaged<CFError>? = nil
        if #available(iOS 11.3, *) {
            secObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryAny, &error)
        } else {
            secObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .touchIDAny, &error)
        }
        guard error == nil else {
            result(FlutterError(code: Constants.authFailed, message: "SecItemAdd can't create secObject: \(error!)", details: nil))
            return
        }
        guard let secObject = secObject else {
            result(FlutterError(code: Constants.authFailed, message: "Error creating SecAccessControl object", details: nil))
            return
        }
        
        let keyAttributes = [
            kSecClass as AnyHashable: kSecClassKey,
            kSecAttrKeyType as AnyHashable: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as AnyHashable: NSNumber(value: 2048),
            kSecPrivateKeyAttrs as AnyHashable: [
                kSecAttrIsPermanent as AnyHashable: NSNumber(value: true),
                kSecUseAuthenticationUI as AnyHashable: kSecUseAuthenticationUIAllow,
                kSecAttrApplicationTag as AnyHashable: tag,
                kSecAttrAccessControl as AnyHashable: secObject
            ] as Any
        ] as CFDictionary
        
        self.deleteBiometricKey()
        var privateKey: SecKey?
        if let attributes = keyAttributes as? CFDictionary {
            privateKey = SecKeyCreateRandomKey(attributes, &error)
        }
        
        guard error == nil else {
            result(FlutterError(code: Constants.authFailed, message: "Error generating public-private keys", details: nil))
            return
        }
        
        guard let privateKey = privateKey, let publicKey = SecKeyCopyPublicKey(privateKey) else {
            result(FlutterError(code: Constants.authFailed, message: "Error generating public-private keys", details: nil))
            return
        }
        
        guard let publicKeyDataRef = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            result(FlutterError(code: Constants.authFailed, message: "Error generating public-private keys", details: nil))
            return
        }
        
        let publicKeyDataWithHeader = BiometricSignaturePlugin.addHeader(publicKeyData: publicKeyDataRef)
        let publicKeyString = publicKeyDataWithHeader!.base64EncodedString(options: [])
        result(publicKeyString)
    }
    
    private func deleteBiometricKey() -> OSStatus {
        let tag = self.getBiometricKeyTag()
        let query = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA
        ] as [String : Any]
        return SecItemDelete(query as CFDictionary)
    }
    
private func createSignature(options: [String: String]?, result: @escaping FlutterResult) {
    let promptMessage = options?["promptMessage"] ?? "Welcome"
    guard let payload = options?["payload"],
          let dataToSign = payload.data(using: .utf8) else {
        result(FlutterError(code: Constants.invalidPayload, message: "Payload is required and must be valid UTF-8", details: nil))
        return
    }

    let tag = getBiometricKeyTag()
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecReturnRef as String: true,
        kSecUseOperationPrompt as String: promptMessage
    ]

    var privateKey: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &privateKey)

    guard status == errSecSuccess else {
        let errorMessage = status == errSecUserCanceled ? "User canceled the authentication" : "Key not found: \(Int(status))"
        result(FlutterError(code: Constants.authFailed, message: errorMessage, details: nil))
        return
    }
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(privateKey as! SecKey, .rsaSignatureMessagePKCS1v15SHA256, dataToSign as CFData, &error) as Data? else {
        let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
        result(FlutterError(code: Constants.authFailed, message: "Error generating signature: \(errorDescription)", details: nil))
        return
    }

    result(signature.base64EncodedString())
}
    
    private func getBiometricType(_ context: LAContext?) -> String {
        return context?.biometryType == .faceID ? "FaceID" : context?.biometryType == .touchID ? "TouchID" : "none, no biometrics available"
    }
    
    private func getBiometricKeyTag() -> Data? {
        let BIOMETRIC_KEY_ALIAS = "biometric_key"
        let tag = BIOMETRIC_KEY_ALIAS.data(using: .utf8)
        return tag
    }
    
    private func doesBiometricKeyExist(checkValidity: Bool = false) -> Bool {
        let tag = getBiometricKeyTag()
        let searchQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: kCFBooleanTrue!,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(searchQuery as CFDictionary, &item)

        guard status == errSecSuccess || status == errSecInteractionNotAllowed, let key = item else {
            return false
        }
        if !checkValidity {
            return true
        }

        do {
            let key = key as! SecKey
            let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
            let message = "test".data(using: .utf8)!

            var error: Unmanaged<CFError>?
            guard SecKeyIsAlgorithmSupported(key, .encrypt, algorithm) else {
                return false
            }

            _ = SecKeyCreateEncryptedData(key, algorithm, message as CFData, &error)
            if let error = error {
                throw error.takeRetainedValue() as Error
            }

            return true
        } catch {
            return false
        }
    }
    
    private static let encodedRSAEncryptionOID: [UInt8] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    ]
    
    private static func addHeader(publicKeyData: Data?) -> Data? {
        var builder = [UInt8](repeating: 0, count: 15)
        var encKey = Data()
        let bitstringEncLength: UInt
        if (publicKeyData?.count ?? 0) + 1 < 128 {
            bitstringEncLength = 1
        } else {
            bitstringEncLength = UInt((((publicKeyData?.count ?? 0) + 1) / 256) + 2)
        }
        builder[0] = 0x30
        let i = encodedRSAEncryptionOID.count + 2 + Int(bitstringEncLength) + (publicKeyData?.count ?? 0)
        var j = encodedLength(&builder[1], i)
        encKey.append(&builder, count: Int(j + 1))
        encKey.append(
            encodedRSAEncryptionOID,
            count: encodedRSAEncryptionOID.count
        )
        builder[0] = 0x03
        j = encodedLength(&builder[1], (publicKeyData?.count ?? 0) + 1)
        builder[j + 1] = 0x00
        encKey.append(&builder, count: Int(j + 2))
        if let publicKeyData = publicKeyData {
            encKey.append(publicKeyData)
        }
        return encKey
    }
    
    private static func encodedLength(_ buf: UnsafeMutablePointer<UInt8>?, _ length: size_t) -> size_t {
        var length = length
        if length < 128 {
            buf?[0] = UInt8(length)
            return 1
        }
        let i: size_t = (length / 256) + 1
        buf?[0] = UInt8(i + 0x80)
        for j in 0..<i {
            buf?[i - j] = UInt8(length & 0xff)
            length = size_t(length >> 8)
        }
        return size_t(i + 1)
    }
}
