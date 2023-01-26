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
              createKeys(result)
          case "createSignature":
              createSignature(call.arguments, result)
          case "deleteKeys":
              result(FlutterMethodNotImplemented)
          case "biometricAuthAvailable":
              biometricAuthAvailable(result)
          case "biometricKeysExist":
              biometricKeysExist(result)
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
    
    
    func biometricKeysExist(result: @escaping FlutterResult) -> Void{
        DispatchQueue.global(qos: .default).async(execute: { [self] in
            let biometricKeyExists = self.doesBiometricKeyExist()
            if (biometricKeyExists) {
                let resultBoolean = true
                result(resultBoolean)
            } else {
                let resultBoolean = false
                result(resultBoolean)
            }
        })
    }


      private func createKeys(result: @escaping FlutterResult) -> Void  {
          DispatchQueue.global(qos: .default).async(execute: { [self] in
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
                  let biometricKeyTag = getBiometricKeyTag()
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
                  deleteBiometricKey()
                  var gen_error: Unmanaged<CFError>?
                  var privateKey: Any? = nil
                  if let attributes = keyAttributes as? CFDictionary? {
                      privateKey = SecKeyCreateRandomKey(attributes!, &gen_error)
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
                          let publicKeyDataWithHeader = AppDelegate.addHeaderPublickey(publicKeyData)
                          let publicKeyString = publicKeyDataWithHeader?.base64EncodedString(options: [])

                          let resultMap = [
                              "publicKey": publicKeyString ?? ""
                          ]
                          result(resultMap)
                      } else {
                          let platformError = FlutterError(code: "AUTHFAILED",
                                                           message: "Key generation error: \(gen_error)",
                                                           details: nil)
                          result(platformError)
                      }
                      return
                  }
              }
          })
      }

      private func createSignature(params: Dictionary<String, String>, result: @escaping FlutterResult) -> Void  {
          DispatchQueue.global(qos: .default).async(execute: { [self] in
              let promptMessage = params["promptMessage"]
              let payload = params["payload"] as? String

              let biometricKeyTag = getBiometricKeyTag()
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
                  let dataToSign = payload!.data(using: .utf8)
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
          let biometricKeyTag = getBiometricKeyTag()
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
          if #available(iOS 11, *) {
              return (context?.biometryType == .faceID) ? "FaceID" : "TouchID"
          }

          return "TouchID"
      }

      private func getBiometricKeyTag() -> Data? {
          let biometricKeyAlias = "biometric_key"
          let biometricKeyTag = biometricKeyAlias.data(using: .utf8)
          return biometricKeyTag
      }
    
    func doesBiometricKeyExist() -> Bool {
        let biometricKeyTag = getBiometricKeyTag()
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

      static let addHeaderPublickey_encodedRSAEncryptionOID:[UInt8] = [    // Sequence of length 0xd made up of OID followed by NULL
          0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

      static func addHeaderPublickey(_ publicKeyData: Data?) -> Data? {

          var builder = [UInt8](repeating: 0, count: 15)
          var encKey = Data()
          var bitstringEncLength: UInt
          // When we get to the bitstring - how will we encode it?
          if (publicKeyData?.count ?? 0) + 1 < 128 {
              bitstringEncLength = 1
          } else {
              bitstringEncLength = UInt((((publicKeyData?.count ?? 0) + 1) / 256) + 2)
          }
          //
          //        // Overall we have a sequence of a certain length
          builder[0] = 0x30 // ASN.1 encoding representing a SEQUENCE
          //        // Build up overall size made up of -
          //        // size of OID + size of bitstring encoding + size of actual key
          let i = MemoryLayout.size(ofValue: addHeaderPublickey_encodedRSAEncryptionOID) + 2 + Int(bitstringEncLength) + (publicKeyData?.count ?? 0)
          var j = encodeLength(&builder[1], i)
          encKey.append(&builder, count: Int(j + 1))

          // First part of the sequence is the OID
          encKey.append(
              addHeaderPublickey_encodedRSAEncryptionOID,
              count: MemoryLayout.size(ofValue: addHeaderPublickey_encodedRSAEncryptionOID))

          // Now add the bitstring
          builder[0] = 0x03
          j = encodeLength(&builder[1], (publicKeyData?.count ?? 0) + 1)
          builder[j + 1] = 0x00
          encKey.append(&builder, count: Int(j + 2))

          // Now the actual key
          if let publicKeyData {
              encKey.append(publicKeyData)
          }

          return encKey
      }

      static func encodeLength(_ buf: UnsafeMutablePointer<UInt8>?, _ length: size_t) -> size_t {
          var length = length

          // encode length in ASN.1 DER format
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
      func keychainError(error:  OSStatus) -> String {
          return String(format: "%ld", Int(error))
      }
}
