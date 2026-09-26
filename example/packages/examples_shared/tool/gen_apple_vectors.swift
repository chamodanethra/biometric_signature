// Generates Apple ECIES and RSA-OAEP test vectors with the Security
// framework, using the exact algorithms the plugin's iOS/macOS code uses:
//   - .eciesEncryptionStandardX963SHA256AESGCM (Secure Enclave EC keys)
//   - .rsaEncryptionOAEPSHA256                  (wrapped RSA keys)
// Software keys are used (no Secure Enclave), so the private keys can be
// exported for the Dart tests. The algorithms are identical.
//
// Usage (macOS):
//   swift tool/gen_apple_vectors.swift > test/fixtures/vectors/apple_vectors.json
//   swift tool/gen_apple_vectors.swift decrypt-ecies <x963PrivateKeyHex> <payloadBase64>
//   swift tool/gen_apple_vectors.swift decrypt-oaep <pkcs1PrivateKeyBase64> <payloadBase64>
// The decrypt modes cross-check ciphertexts produced by the Dart code.

import Foundation
import Security

func fail(_ message: String) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(1)
}

func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

func fromHex(_ s: String) -> Data {
    var data = Data()
    var index = s.startIndex
    while index < s.endIndex {
        let next = s.index(index, offsetBy: 2)
        data.append(UInt8(s[index..<next], radix: 16)!)
        index = next
    }
    return data
}

func makeKey(type: CFString, bits: Int) -> SecKey {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: type,
        kSecAttrKeySizeInBits as String: bits,
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        fail("key generation failed: \(error!.takeRetainedValue())")
    }
    return key
}

func export(_ key: SecKey) -> Data {
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
        fail("export failed: \(error!.takeRetainedValue())")
    }
    return data
}

func importKey(_ data: Data, type: CFString, keyClass: CFString) -> SecKey {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: type,
        kSecAttrKeyClass as String: keyClass,
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
        fail("import failed: \(error!.takeRetainedValue())")
    }
    return key
}

func encrypt(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ plaintext: Data) -> Data {
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCreateEncryptedData(key, algorithm, plaintext as CFData, &error) as Data? else {
        fail("encrypt failed: \(error!.takeRetainedValue())")
    }
    return data
}

func decrypt(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ ciphertext: Data) -> Data {
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCreateDecryptedData(key, algorithm, ciphertext as CFData, &error) as Data? else {
        fail("decrypt failed: \(error!.takeRetainedValue())")
    }
    return data
}

let ecies = SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM
let oaep = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
let args = CommandLine.arguments

if args.count == 4 && args[1] == "decrypt-ecies" {
    let key = importKey(fromHex(args[2]), type: kSecAttrKeyTypeECSECPrimeRandom, keyClass: kSecAttrKeyClassPrivate)
    let plain = decrypt(key, ecies, Data(base64Encoded: args[3])!)
    print(String(data: plain, encoding: .utf8) ?? "<non-UTF-8 \(hex(plain))>")
    exit(0)
}
if args.count == 4 && args[1] == "decrypt-oaep" {
    let key = importKey(Data(base64Encoded: args[2])!, type: kSecAttrKeyTypeRSA, keyClass: kSecAttrKeyClassPrivate)
    let plain = decrypt(key, oaep, Data(base64Encoded: args[3])!)
    print(String(data: plain, encoding: .utf8) ?? "<non-UTF-8 \(hex(plain))>")
    exit(0)
}
if args.count != 1 { fail("unknown arguments") }

let plaintext = "Sealed for the Secure Enclave: ECIES test vector \u{1F510}"
let ecKey = makeKey(type: kSecAttrKeyTypeECSECPrimeRandom, bits: 256)
let ecPublic = SecKeyCopyPublicKey(ecKey)!
let eciesPayload = encrypt(ecPublic, ecies, plaintext.data(using: .utf8)!)
precondition(decrypt(ecKey, ecies, eciesPayload) == plaintext.data(using: .utf8)!)

let oaepPlaintext = "RSA-OAEP SHA-256 / MGF1-SHA-256 test vector"
let rsaKey = makeKey(type: kSecAttrKeyTypeRSA, bits: 2048)
let rsaPublic = SecKeyCopyPublicKey(rsaKey)!
let oaepPayload = encrypt(rsaPublic, oaep, oaepPlaintext.data(using: .utf8)!)
precondition(decrypt(rsaKey, oaep, oaepPayload) == oaepPlaintext.data(using: .utf8)!)

let output: [String: Any] = [
    "generator": "tool/gen_apple_vectors.swift",
    "ecies": [
        "algorithm": "eciesEncryptionStandardX963SHA256AESGCM",
        // 04 || X || Y || D (SecKeyCopyExternalRepresentation of the private key)
        "privateKeyX963": hex(export(ecKey)),
        "publicKeyX963": hex(export(ecPublic)),
        "plaintext": plaintext,
        "payload": eciesPayload.base64EncodedString(),
    ],
    "rsaOaep": [
        "algorithm": "rsaEncryptionOAEPSHA256",
        // PKCS#1 RSAPrivateKey DER
        "privateKeyPkcs1": export(rsaKey).base64EncodedString(),
        "plaintext": oaepPlaintext,
        "payload": oaepPayload.base64EncodedString(),
    ],
]
let json = try! JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys])
print(String(data: json, encoding: .utf8)!)
