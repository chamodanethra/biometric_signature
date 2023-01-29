import Flutter
import UIKit
import LocalAuthentication
import Security

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
            biometricKeyExists(result: result)
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
    
    private func biometricKeyExists(result: @escaping FlutterResult) {
        let biometricKeyExists = self.doesBiometricKeyExist()
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
        if let error = error {
            result(FlutterError(code: "AUTHFAILED", message: "SecItemAdd can't create secObject: \(error)", details: nil))
            return
        }
        if let secObject = secObject {
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
            var privateKey: SecKey? = nil
            if let attributes = keyAttributes as? CFDictionary {
                privateKey = SecKeyCreateRandomKey(attributes, &error)
            }
            if let error = error {
                result(FlutterError(code: "AUTHFAILED", message: "Error generating public private keys", details: nil))
                return
            }
            if let privateKey = privateKey, let publicKey = SecKeyCopyPublicKey(privateKey) {
                var publicKeyDataRef: CFData? = nil
                publicKeyDataRef = SecKeyCopyExternalRepresentation(publicKey as! SecKey, nil)
                if let publicKeyDataRef = publicKeyDataRef as? Data {
                    let publicKeyDataWithHeader = BiometricSignaturePlugin.addHeader(publicKeyData: publicKeyDataRef)
                    let publicKeyString = publicKeyDataWithHeader!.base64EncodedString(options: [])
                    result(publicKeyString)
                    return
                }
            }
        }
        result(FlutterError(code: "AUTHFAILED", message: "Error generating public private keys", details: nil))
    }

    
    private func createSignature(options: Dictionary<String, String>?, result: @escaping FlutterResult) {
        let promptMessage = options?["promptMessage"] ?? "Welcome"
        let payload = "arhten adomahc"
        let tag = getBiometricKeyTag()
        let query: [AnyHashable: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecReturnRef: NSNumber(value: true),
            kSecUseOperationPrompt: promptMessage
        ]
        
        var privateKey: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &privateKey)
        
        if status == errSecSuccess {
            let dataToSign = payload.data(using: .utf8)
            guard let signature = SecKeyCreateSignature(privateKey as! SecKey, .rsaSignatureMessagePKCS1v15SHA256, dataToSign! as CFData, nil) as Data? else {
                if status == Int(errSecUserCanceled) {
                    result(FlutterError(code: "USERCANCEL", message: "userCancel", details: nil))
                } else {
                    result(FlutterError(code: "AUTHFAILED", message: "Error generating signature", details: nil))
                }
                return
            }
            result(signature.base64EncodedString())
        } else {
            result(FlutterError(code: "AUTHFAILED", message: "Key not found: \(Int(status))", details: nil))
        }
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
    
    private func getBiometricType(_ context: LAContext?) -> String {
        return (context?.biometryType == .faceID) ? "FaceID" : "TouchID"
    }
    
    private func getBiometricKeyTag() -> Data? {
        let BIOMETRIC_KEY_ALIAS = "biometric_key"
        let tag = BIOMETRIC_KEY_ALIAS.data(using: .utf8)
        return tag
    }
    
    private func doesBiometricKeyExist() -> Bool {
        let tag = getBiometricKeyTag()
        let searchQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(searchQuery as CFDictionary, &item)
        return status == errSecSuccess
    }
    
    private static let encodedRSAEncryptionOID:[UInt8] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
    
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
        let i = MemoryLayout.size(ofValue: encodedRSAEncryptionOID) + 2 + Int(bitstringEncLength) + (publicKeyData?.count ?? 0)
        let j = encodedLength(i)
        encKey.append(&builder, count: Int(j + 1))
        encKey.append(
            encodedRSAEncryptionOID,
            count: MemoryLayout.size(ofValue: encodedRSAEncryptionOID))
        builder[0] = 0x03
        let k = encodedLength((publicKeyData?.count ?? 0) + 1)
        builder[Int(k)] = 0x00
        encKey.append(&builder, count: Int(k + 1))
        if let publicKeyData {
            encKey.append(publicKeyData)
        }
        return encKey
    }

    private static func encodedLength(_ length: size_t) -> size_t {
        var length = length
        var buf = [UInt8](repeating: 0, count: 32)
        var i = 0
        if length < 128 {
            buf[0] = UInt8(length)
            return 1
        }
        i = Int((length / 256)) + 1
        buf[0] = UInt8(i + 0x80)
        for j in 0..<i {
            buf[i - j] = UInt8(length & 0xff)
            length = size_t(length >> 8)
        }
        return size_t(i + 1)
    }
}
