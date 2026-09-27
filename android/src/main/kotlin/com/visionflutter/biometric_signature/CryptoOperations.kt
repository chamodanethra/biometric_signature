package com.visionflutter.biometric_signature

import androidx.biometric.BiometricPrompt
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class CryptoOperations(
    private val fileIO: FileIOHelper
) {

    fun getCipherForEncryption(keyAlias: String?): Cipher {
        val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
        val masterAlias = Constants.masterKeyAlias(keyAlias)
        val masterKey = keyStore.getKey(masterAlias, null) as? SecretKey
            ?: throw IllegalStateException("Master key not found")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
        return cipher
    }

    fun getCipherForDecryption(keyAlias: String?): Cipher? {
        val wrappedFilename = Constants.ecWrappedFilename(keyAlias)
        val wrapped = fileIO.readFileIfExists(wrappedFilename) ?: return null
        if (wrapped.size < Constants.GCM_IV_SIZE + 1 + Constants.GCM_TAG_BYTES) return null

        val iv = wrapped.copyOfRange(0, Constants.GCM_IV_SIZE)
        val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
        val masterAlias = Constants.masterKeyAlias(keyAlias)
        val masterKey = keyStore.getKey(masterAlias, null) as? SecretKey ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(Constants.GCM_TAG_BITS, iv))
        return cipher
    }

    fun generateAndSealDecryptionEcKeyLocal(cipher: Cipher): Pair<ByteArray, ByteArray> {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val keyPair = kpg.generateKeyPair()

        val privateKeyBytes = keyPair.private.encoded
        val publicKeyBytes = keyPair.public.encoded

        try {
            val encrypted = cipher.doFinal(privateKeyBytes)
            val iv = cipher.iv ?: throw IllegalStateException("Cipher IV missing")
            val wrapped = ByteArray(iv.size + encrypted.size)
            System.arraycopy(iv, 0, wrapped, 0, iv.size)
            System.arraycopy(encrypted, 0, wrapped, iv.size, encrypted.size)
            return Pair(wrapped, publicKeyBytes)
        } finally {
            privateKeyBytes.fill(0)
        }
    }

    fun prepareSignature(keyAlias: String?, mode: KeyMode): Pair<Signature, BiometricPrompt.CryptoObject> {
        val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
        val alias = Constants.biometricKeyAlias(keyAlias)
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw KeyNotFoundException("Signing key not found")

        val algorithm = when (mode) {
            KeyMode.RSA -> "SHA256withRSA"
            else -> "SHA256withECDSA"
        }

        val signature = Signature.getInstance(algorithm)
        signature.initSign(entry.privateKey)
        return Pair(signature, BiometricPrompt.CryptoObject(signature))
    }

    fun getSigningPublicKey(keyAlias: String?): PublicKey {
        val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
        val alias = Constants.biometricKeyAlias(keyAlias)
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw KeyNotFoundException("Signing key not found")
        return entry.certificate.publicKey
    }

    /**
     * Throws [IllegalArgumentException] (mapped to `INVALID_INPUT`) unless [data] is
     * framed like an ECIES payload: a 65-byte uncompressed ephemeral public key, then
     * the ciphertext and the 16-byte GCM tag.
     */
    fun requireEciesPayload(data: ByteArray) {
        require(data.size >= Constants.EC_PUBKEY_SIZE + Constants.GCM_TAG_BYTES) {
            "Invalid ECIES payload: too short (${data.size} bytes)"
        }
        require(data[0] == 0x04.toByte()) {
            "Invalid ECIES payload: the ephemeral key must be uncompressed (0x04)"
        }
    }

    fun performEciesDecryption(
        keyAlias: String?,
        unwrapCipher: Cipher,
        data: ByteArray
    ): String {
        requireEciesPayload(data)
        val wrappedFilename = Constants.ecWrappedFilename(keyAlias)
        val wrapped = fileIO.readFileIfExists(wrappedFilename)
            ?: throw KeyNotFoundException("Encrypted EC key not found")
        if (wrapped.size < Constants.GCM_IV_SIZE + 1) throw IllegalStateException("Malformed wrapped blob")

        val encryptedKey = wrapped.copyOfRange(Constants.GCM_IV_SIZE, wrapped.size)

        var privateKeyBytes: ByteArray? = null
        try {
            privateKeyBytes = unwrapCipher.doFinal(encryptedKey)

            val privateKey: PrivateKey = KeyFactory.getInstance("EC")
                .generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

            val ephemeralKeyBytes = data.copyOfRange(0, Constants.EC_PUBKEY_SIZE)

            val ciphertextWithTag = data.copyOfRange(Constants.EC_PUBKEY_SIZE, data.size)

            val ephemeralPubKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(createX509ForRawEcPub(ephemeralKeyBytes)))

            val sharedSecret: ByteArray = KeyAgreement.getInstance("ECDH").run {
                init(privateKey)
                doPhase(ephemeralPubKey, true)
                generateSecret()
            }

            val derived: ByteArray = try {
                kdfX963(sharedSecret, Constants.AES_KEY_SIZE + Constants.GCM_IV_SIZE)
            } finally {
                sharedSecret.fill(0)
            }

            val aesKeyBytes = derived.copyOfRange(0, Constants.AES_KEY_SIZE)
            val gcmIv = derived.copyOfRange(Constants.AES_KEY_SIZE, Constants.AES_KEY_SIZE + Constants.GCM_IV_SIZE)
            derived.fill(0)

            try {
                val aesKey = SecretKeySpec(aesKeyBytes, "AES")
                val decrypted = Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(Constants.GCM_TAG_BITS, gcmIv))
                    doFinal(ciphertextWithTag)
                }
                return String(decrypted, Charsets.UTF_8)
            } finally {
                aesKeyBytes.fill(0)
                gcmIv.fill(0)
            }
        } finally {
            privateKeyBytes?.fill(0)
        }
    }

    private fun createX509ForRawEcPub(raw: ByteArray): ByteArray {
        val header = byteArrayOf(
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A.toByte(), 0x86.toByte(),
            0x48.toByte(), 0xCE.toByte(), 0x3D.toByte(), 0x02.toByte(), 0x01.toByte(),
            0x06.toByte(), 0x08.toByte(), 0x2A.toByte(), 0x86.toByte(), 0x48.toByte(),
            0xCE.toByte(), 0x3D.toByte(), 0x03.toByte(), 0x01.toByte(), 0x07.toByte(),
            0x03.toByte(), 0x42.toByte(), 0x00.toByte()
        )
        val out = ByteArray(header.size + raw.size)
        System.arraycopy(header, 0, out, 0, header.size)
        System.arraycopy(raw, 0, out, header.size, raw.size)
        return out
    }

    private fun kdfX963(secret: ByteArray, length: Int): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val result = ByteArray(length)
        var offset = 0
        var counter = 1

        while (offset < length) {
            digest.reset()
            digest.update(secret)
            digest.update(
                byteArrayOf(
                    (counter shr 24).toByte(),
                    (counter shr 16).toByte(),
                    (counter shr 8).toByte(),
                    counter.toByte()
                )
            )
            val hash = digest.digest()
            val toCopy = minOf(hash.size, length - offset)
            System.arraycopy(hash, 0, result, offset, toCopy)
            offset += toCopy
            counter++
        }
        return result
    }
}
