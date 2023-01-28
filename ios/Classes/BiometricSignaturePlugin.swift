import Flutter
import UIKit
import LocalAuthentication
import Security

@available(iOS 11.3, *)
public class BiometricSignaturePlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "biometric_signature", binaryMessenger: registrar.messenger())
        let instance = BiometricSignaturePlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "createKeys":
            self.createKeys(result: result)
        case "createSignature":
            self.createSignature(options: call.arguments as? Dictionary<String, String>, result: result)
        case "deleteKeys":
            self.deleteKeys(result: result)
        case "biometricAuthAvailable":
            self.biometricAuthAvailable(result: result)
        case "biometricKeysExist":
            self.biometricKeysExist(result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
    private func biometricAuthAvailable(result: @escaping FlutterResult) -> Void  {
        let context = LAContext()
        var la_error: NSError?
        let canEvaluatePolicy = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &la_error)
        
        var resultMap = [String : String]()
        if canEvaluatePolicy {
            let biometryType = getBiometryType(context)
            resultMap = [
                "biometricsType": biometryType
            ]
        } else {
            var errorMessage: String? = nil
            if let la_error {
                errorMessage = "\(la_error)"
            }
            resultMap = [
                "biometricsType": "none",
                "error": errorMessage ?? ""
            ]
        }
        result(resultMap)
        return
    }
    
    private func biometricKeysExist(result: @escaping FlutterResult) -> Void{
        DispatchQueue.global().async(execute: { [self] in
            let biometricKeyExists = self.doesBiometricKeyExist()
            if biometricKeyExists {
                let resultBoolean = true
                result(resultBoolean)
            } else {
                let resultBoolean = false
                result(resultBoolean)
            }
        })
    }
    
    private func deleteKeys(result: @escaping FlutterResult) -> Void  {
        DispatchQueue.global().async(execute: { [self] in
            let biometricKeyExists = self.doesBiometricKeyExist()
            if biometricKeyExists {
                var status = self.deleteBiometricKey()
                print(status)
                result(status == noErr)
            }
        })
    }
    
    
    private func createKeys(result: @escaping FlutterResult) -> Void  {
        DispatchQueue.global().async(execute: { [self] in
            var error: Unmanaged<CFError>? = nil
            let sacObject = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                .biometryAny,
                &error)
            if sacObject == nil || error != nil {
                var errorString: String? = nil
                if let error {
                    errorString = "SecItemAdd can't create sacObject: \(error)"
                    
                    let platformError = FlutterError(code: "AUTHFAILED",
                                                     message: errorString,
                                                     details: nil)
                    result(platformError)
                    return
                }
            }else {
                let biometricKeyTag = getBiometricKey()
                var keyAttributes: [AnyHashable? : Any?]? = nil
                if let kSecClass = kSecClass as? AnyHashable, let kSecClassKey = kSecClassKey as? AnyHashable, let kSecAttrKeyType = kSecAttrKeyType as? AnyHashable, let kSecAttrKeyTypeRSA=kSecAttrKeyTypeRSA as? AnyHashable, let kSecAttrKeySizeInBits = kSecAttrKeySizeInBits as? AnyHashable, let kSecPrivateKeyAttrs = kSecPrivateKeyAttrs as? AnyHashable, let kSecAttrIsPermanent = kSecAttrIsPermanent as? AnyHashable, let kSecUseAuthenticationUI = kSecUseAuthenticationUI as? AnyHashable, let kSecUseAuthenticationUIAllow = kSecUseAuthenticationUIAllow as? AnyHashable, let kSecAttrApplicationTag = kSecAttrApplicationTag as? AnyHashable, let biometricKeyTag, let kSecAttrAccessControl = kSecAttrAccessControl as? AnyHashable, let sacObject {
                    keyAttributes = [
                        kSecClass: kSecClassKey,
                        kSecAttrKeyType: kSecAttrKeyTypeRSA,
                        kSecAttrKeySizeInBits: NSNumber(value: 2048),
                        kSecPrivateKeyAttrs: [
                            kSecAttrIsPermanent: NSNumber(value: true),
                            kSecUseAuthenticationUI: kSecUseAuthenticationUIAllow,
                            kSecAttrApplicationTag: biometricKeyTag,
                            kSecAttrAccessControl: sacObject
                        ] as? Any
                    ]
                }
                var status = self.deleteBiometricKey()
                print(status)
                var error: Unmanaged<CFError>?
                var privateKey: Any? = nil
                if let attributes = keyAttributes as? CFDictionary? {
                    privateKey = SecKeyCreateRandomKey(attributes!, &error)
                    if let privateKey {
                        var publicKey: Any? = nil
                        if let key = privateKey as? SecKey? {
                            publicKey = SecKeyCopyPublicKey(key!)
                        }
                        var publicKeyDataRef: CFData? = nil
                        if let key = publicKey {
                            publicKeyDataRef = SecKeyCopyExternalRepresentation(key as! SecKey, nil)
                        }
                        let publicKeyData = publicKeyDataRef as? Data
                        let publicKeyDataWithHeader = BiometricSignaturePlugin.addHeaderPublickey(publicKeyData)
                        let publicKeyString = publicKeyDataWithHeader?.base64EncodedString(options: [])
                        
                        let resultMap = [
                            "publicKey": publicKeyString ?? ""
                        ]
                        result(resultMap)
                    } else {
                        let platformError = FlutterError(code: "AUTHFAILED",
                                                         message: "Key generation error: \(error)",
                                                         details: nil)
                        result(platformError)
                    }
                    return
                }
            }
        })
    }
    
    private func createSignature(options: Dictionary<String, String>?, result: @escaping FlutterResult) -> Void  {
        DispatchQueue.global().async(execute: { [self] in
            let promptMessage = options?["promptMessage"] ?? "Welcome"
            let payload = "arhten adomahc"
            let biometricKeyTag = getBiometricKey()
            var query: [AnyHashable? : Any?]? = nil
            if let kSecClass = kSecClass as? AnyHashable, let kSecClassKey = kSecClassKey as? AnyHashable, let kSecAttrApplicationTag = kSecAttrApplicationTag as? AnyHashable, let biometricKeyTag, let kSecAttrKeyType = kSecAttrKeyType as? AnyHashable, let kSecAttrKeyTypeRSA = kSecAttrKeyTypeRSA as? AnyHashable, let kSecReturnRef = kSecReturnRef as? AnyHashable, let kSecUseOperationPrompt = kSecUseOperationPrompt as? AnyHashable {
                query = [
                    kSecClass: kSecClassKey,
                    kSecAttrApplicationTag: biometricKeyTag,
                    kSecAttrKeyType: kSecAttrKeyTypeRSA,
                    kSecReturnRef: NSNumber(value: true),
                    kSecUseOperationPrompt: promptMessage
                ]
            }
            var privateKey: AnyObject?
            var status: OSStatus? = nil
            if let query = query as? CFDictionary? {
                status = SecItemCopyMatching(query!, &privateKey)
            }
            if status == errSecSuccess {
                var error: NSError?
                let dataToSign = payload.data(using: .utf8)
                var signature: Data? = nil
                if let sign = dataToSign as? CFData? {
                    signature = SecKeyCreateSignature(privateKey as! SecKey, .rsaSignatureMessagePKCS1v15SHA256, sign!, nil)! as Data
                }
                var resultMap = [String : String]()
                if let signature {
                    let signatureString = signature.base64EncodedString(options: [])
                    resultMap = [
                        "signature": signatureString
                    ]
                    result(resultMap)
                } else if (error as NSError?)?.code == Int(errSecUserCanceled) {
                    let platformError = FlutterError(code: "useCancel",
                                                     message: "userCancel",
                                                     details: nil)
                    result(platformError)
                } else {
                    if let error {
                        let message = "Error generating signature: \(error)"
                        let platformError = FlutterError(code: "AUTHFAILED",
                                                         message: message,
                                                         details: nil)
                        result(platformError)
                    }
                }
            } else {
                let message = "Key not found: \(keychainError(error: status!))"
                let platformError = FlutterError(code: "AUTHFAILED",
                                                 message: message,
                                                 details: nil)
                result(platformError)
            }
            return
        })
    }
    
    private func deleteBiometricKey() -> OSStatus {
            let biometricKeyTag = getBiometricKey()
            var deleteQuery: [AnyHashable? : Any?]? = nil
            if let kSecClass = kSecClass as? AnyHashable, let kSecClassKey = kSecClassKey as? AnyHashable, let kSecAttrApplicationTag = kSecAttrApplicationTag as? AnyHashable, let kSecAttrKeyType = kSecAttrKeyType as? AnyHashable, let kSecAttrKeyTypeRSA = kSecAttrKeyTypeRSA as? AnyHashable {
                deleteQuery = [
                    kSecClass: kSecClassKey,
                    kSecAttrApplicationTag: biometricKeyTag,
                    kSecAttrKeyType: kSecAttrKeyTypeRSA
                ]
            }
            var status: OSStatus? = nil
            if let query = deleteQuery as? CFDictionary? {
                status = SecItemDelete(query!)
            }
            return status!
        }
    
    private func getBiometryType(_ context: LAContext?) -> String {
        return (context?.biometryType == .faceID) ? "FaceID" : "TouchID"
    }
    
    private func getBiometricKey() -> Data? {
        let BIOMETRIC_KEY_ALIAS = "biometric_key"
        let biometricKeyTag = BIOMETRIC_KEY_ALIAS.data(using: .utf8)
        return biometricKeyTag
    }
    
    private func doesBiometricKeyExist() -> Bool {
        let biometricKeyTag = getBiometricKey()
        let searchQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: biometricKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(searchQuery as CFDictionary, &item)
        return status == errSecSuccess
    }
    
    private static let addHeaderPublickey_encodedRSAEncryptionOID:[UInt8] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
    
    private static func addHeaderPublickey(_ publicKeyData: Data?) -> Data? {
        var builder = [UInt8](repeating: 0, count: 15)
        var encKey = Data()
        var bitstringEncLength: UInt
        if (publicKeyData?.count ?? 0) + 1 < 128 {
            bitstringEncLength = 1
        } else {
            bitstringEncLength = UInt((((publicKeyData?.count ?? 0) + 1) / 256) + 2)
        }
        builder[0] = 0x30
        let i = MemoryLayout.size(ofValue: addHeaderPublickey_encodedRSAEncryptionOID) + 2 + Int(bitstringEncLength) + (publicKeyData?.count ?? 0)
        var j = encodedLength(&builder[1], i)
        encKey.append(&builder, count: Int(j + 1))
        
        encKey.append(
            addHeaderPublickey_encodedRSAEncryptionOID,
            count: MemoryLayout.size(ofValue: addHeaderPublickey_encodedRSAEncryptionOID))
        builder[0] = 0x03
        j = encodedLength(&builder[1], (publicKeyData?.count ?? 0) + 1)
        builder[j + 1] = 0x00
        encKey.append(&builder, count: Int(j + 2))
        if let publicKeyData {
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
        let i: size_t = Int((length / 256)) + 1
        buf?[0] = UInt8(i + 0x80)
        for j in 0..<i {
            buf?[i - j] = UInt8(length & 0xff)
            length = size_t(length >> 8)
        }
        return size_t(i + 1)
    }
    
    private func keychainError(error:  OSStatus) -> String {
        return String(format: "%ld", Int(error))
    }
}
