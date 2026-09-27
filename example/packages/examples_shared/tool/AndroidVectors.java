// Generates Android-side ECIES and RSA-OAEP test vectors with the JCA, using
// the same primitives and parameters as the plugin's Android code:
//   - ECIES decrypt: a line-by-line port of
//     CryptoOperations.performEciesDecryption / kdfX963 (plugin
//     android/src/main/kotlin/.../CryptoOperations.kt).
//   - RSA decrypt: "RSA/ECB/OAEPPadding" with SHA-256 and MGF1-SHA-1
//     (Constants.RSA_OAEP_SHA256_MGF1_SHA1).
// Software keys are used so the private keys can be exported for the Dart
// tests.
//
// Usage (JDK 11+):
//   java tool/AndroidVectors.java > test/fixtures/vectors/android_vectors.json
//   java tool/AndroidVectors.java decrypt-ecies <privateScalarHex> <payloadBase64>
//   java tool/AndroidVectors.java decrypt-oaep  <pkcs8Base64> <payloadBase64>
// The decrypt modes cross-check ciphertexts produced by the Dart code.

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public class AndroidVectors {
  static final int EC_PUBKEY_SIZE = 65;
  static final int AES_KEY_SIZE = 16;
  static final int GCM_IV_SIZE = 12;
  static final int GCM_TAG_BITS = 128;
  static final OAEPParameterSpec OAEP_SHA256_MGF1_SHA1 =
      new OAEPParameterSpec(
          "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);

  public static void main(String[] args) throws Exception {
    if (args.length == 3 && args[0].equals("decrypt-ecies")) {
      PrivateKey key = ecPrivate(new java.math.BigInteger(args[1], 16));
      System.out.println(eciesDecrypt(key, Base64.getDecoder().decode(args[2])));
      return;
    }
    if (args.length == 3 && args[0].equals("decrypt-oaep")) {
      PrivateKey key =
          KeyFactory.getInstance("RSA")
              .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(args[1])));
      System.out.println(oaepDecrypt(key, Base64.getDecoder().decode(args[2])));
      return;
    }
    if (args.length != 0) throw new IllegalArgumentException("unknown arguments");

    // ECIES (hybrid mode decrypting key).
    KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
    ecGen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair ec = ecGen.generateKeyPair();
    String eciesPlain = "Android hybrid ECIES test vector 🔑";
    byte[] eciesPayload = eciesEncrypt(ec.getPublic(), eciesPlain.getBytes(StandardCharsets.UTF_8));
    if (!eciesDecrypt(ec.getPrivate(), eciesPayload).equals(eciesPlain)) {
      throw new IllegalStateException("ECIES self-check failed");
    }

    // RSA-OAEP (SHA-256 / MGF1-SHA-1).
    KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
    rsaGen.initialize(2048);
    KeyPair rsa = rsaGen.generateKeyPair();
    String oaepPlain = "RSA-OAEP SHA-256 / MGF1-SHA-1 test vector";
    Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding");
    enc.init(Cipher.ENCRYPT_MODE, rsa.getPublic(), OAEP_SHA256_MGF1_SHA1);
    byte[] oaepPayload = enc.doFinal(oaepPlain.getBytes(StandardCharsets.UTF_8));
    if (!oaepDecrypt(rsa.getPrivate(), oaepPayload).equals(oaepPlain)) {
      throw new IllegalStateException("OAEP self-check failed");
    }

    Base64.Encoder b64 = Base64.getEncoder();
    String d = ((ECPrivateKey) ec.getPrivate()).getS().toString(16);
    System.out.println("{");
    System.out.println("  \"generator\": \"tool/AndroidVectors.java\",");
    System.out.println("  \"ecies\": {");
    System.out.println("    \"privateScalarHex\": \"" + d + "\",");
    System.out.println("    \"publicKeySpki\": \"" + b64.encodeToString(ec.getPublic().getEncoded()) + "\",");
    System.out.println("    \"plaintext\": \"" + escape(eciesPlain) + "\",");
    System.out.println("    \"payload\": \"" + b64.encodeToString(eciesPayload) + "\"");
    System.out.println("  },");
    System.out.println("  \"rsaOaep\": {");
    System.out.println("    \"privateKeyPkcs8\": \"" + b64.encodeToString(rsa.getPrivate().getEncoded()) + "\",");
    System.out.println("    \"publicKeySpki\": \"" + b64.encodeToString(rsa.getPublic().getEncoded()) + "\",");
    System.out.println("    \"plaintext\": \"" + escape(oaepPlain) + "\",");
    System.out.println("    \"payload\": \"" + b64.encodeToString(oaepPayload) + "\"");
    System.out.println("  }");
    System.out.println("}");
  }

  static String escape(String s) {
    StringBuilder sb = new StringBuilder();
    for (char c : s.toCharArray()) {
      if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') {
        sb.append(String.format("\\u%04x", (int) c));
      } else {
        sb.append(c);
      }
    }
    return sb.toString();
  }

  static PrivateKey ecPrivate(java.math.BigInteger d) throws Exception {
    AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
    params.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
    return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(d, spec));
  }

  static String oaepDecrypt(PrivateKey key, byte[] payload) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
    cipher.init(Cipher.DECRYPT_MODE, key, OAEP_SHA256_MGF1_SHA1);
    return new String(cipher.doFinal(payload), StandardCharsets.UTF_8);
  }

  // Encrypt side: the inverse of the plugin's decrypt.
  static byte[] eciesEncrypt(PublicKey recipient, byte[] plaintext) throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair eph = gen.generateKeyPair();
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    ka.init(eph.getPrivate());
    ka.doPhase(recipient, true);
    byte[] derived = kdfX963(ka.generateSecret(), AES_KEY_SIZE + GCM_IV_SIZE);
    byte[] aesKey = java.util.Arrays.copyOfRange(derived, 0, AES_KEY_SIZE);
    byte[] iv = java.util.Arrays.copyOfRange(derived, AES_KEY_SIZE, AES_KEY_SIZE + GCM_IV_SIZE);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
    byte[] sealed = cipher.doFinal(plaintext);
    byte[] ephRaw = rawUncompressed(eph.getPublic().getEncoded());
    byte[] out = new byte[ephRaw.length + sealed.length];
    System.arraycopy(ephRaw, 0, out, 0, ephRaw.length);
    System.arraycopy(sealed, 0, out, ephRaw.length, sealed.length);
    return out;
  }

  static byte[] rawUncompressed(byte[] spki) {
    // The last 65 bytes of a P-256 SubjectPublicKeyInfo are 04 || X || Y.
    return java.util.Arrays.copyOfRange(spki, spki.length - EC_PUBKEY_SIZE, spki.length);
  }

  // Port of CryptoOperations.performEciesDecryption (key unwrap omitted).
  static String eciesDecrypt(PrivateKey privateKey, byte[] data) throws Exception {
    if (data.length < EC_PUBKEY_SIZE + GCM_TAG_BITS / 8) {
      throw new IllegalArgumentException("Invalid ECIES payload: too short");
    }
    byte[] ephemeralKeyBytes = java.util.Arrays.copyOfRange(data, 0, EC_PUBKEY_SIZE);
    if (ephemeralKeyBytes[0] != 0x04) throw new IllegalArgumentException("expected 0x04");
    byte[] ciphertextWithTag = java.util.Arrays.copyOfRange(data, EC_PUBKEY_SIZE, data.length);
    PublicKey ephemeralPubKey =
        KeyFactory.getInstance("EC")
            .generatePublic(new X509EncodedKeySpec(createX509ForRawEcPub(ephemeralKeyBytes)));
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    ka.init(privateKey);
    ka.doPhase(ephemeralPubKey, true);
    byte[] sharedSecret = ka.generateSecret();
    byte[] derived = kdfX963(sharedSecret, AES_KEY_SIZE + GCM_IV_SIZE);
    byte[] aesKeyBytes = java.util.Arrays.copyOfRange(derived, 0, AES_KEY_SIZE);
    byte[] gcmIv = java.util.Arrays.copyOfRange(derived, AES_KEY_SIZE, AES_KEY_SIZE + GCM_IV_SIZE);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKeyBytes, "AES"), new GCMParameterSpec(GCM_TAG_BITS, gcmIv));
    return new String(cipher.doFinal(ciphertextWithTag), StandardCharsets.UTF_8);
  }

  static byte[] createX509ForRawEcPub(byte[] raw) {
    byte[] header = {
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01,
      0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
    };
    byte[] out = new byte[header.length + raw.length];
    System.arraycopy(header, 0, out, 0, header.length);
    System.arraycopy(raw, 0, out, header.length, raw.length);
    return out;
  }

  static byte[] kdfX963(byte[] secret, int length) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] result = new byte[length];
    int offset = 0;
    int counter = 1;
    while (offset < length) {
      digest.reset();
      digest.update(secret);
      digest.update(new byte[] {(byte) (counter >> 24), (byte) (counter >> 16), (byte) (counter >> 8), (byte) counter});
      byte[] hash = digest.digest();
      int toCopy = Math.min(hash.length, length - offset);
      System.arraycopy(hash, 0, result, offset, toCopy);
      offset += toCopy;
      counter++;
    }
    return result;
  }
}
