package com.visionflutter.biometric_signature

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyPair
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.KeyGenerator

class KeyManager(private val appContext: Context, private val fileIO: FileIOHelper) {

    fun generateRsaKeyInKeyStore(
        keyAlias: String?,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enableDecryption: Boolean,
        requireAuthentication: Boolean
    ): KeyPair {
        val purposes = if (enableDecryption) {
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
        } else {
            KeyProperties.PURPOSE_SIGN
        }

        val alias = Constants.biometricKeyAlias(keyAlias)
        val builder = KeyGenParameterSpec.Builder(alias, purposes)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
            .setUserAuthenticationRequired(requireAuthentication)

        if (enableDecryption) {
            builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            tryPinOaepMgf1Digest(builder)
        }

        if (requireAuthentication) {
            configurePerOperationAuth(builder, useDeviceCredentials)
            configureInvalidation(builder, invalidateOnEnrollment)
        }
        tryEnableStrongBox(builder)

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, Constants.KEYSTORE_PROVIDER)
        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    fun generateEcKeyInKeyStore(
        keyAlias: String?,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        requireAuthentication: Boolean
    ): KeyPair {
        val alias = Constants.biometricKeyAlias(keyAlias)
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(requireAuthentication)

        if (requireAuthentication) {
            configurePerOperationAuth(builder, useDeviceCredentials)
            configureInvalidation(builder, invalidateOnEnrollment)
        }
        tryEnableStrongBox(builder)

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, Constants.KEYSTORE_PROVIDER)
        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    fun generateMasterKey(keyAlias: String?, useDeviceCredentials: Boolean, invalidateOnEnrollment: Boolean, requireAuthentication: Boolean) {
        val alias = Constants.masterKeyAlias(keyAlias)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(requireAuthentication)

        if (requireAuthentication) {
            configurePerOperationAuth(builder, useDeviceCredentials)
            configureInvalidation(builder, invalidateOnEnrollment)
        }

        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, Constants.KEYSTORE_PROVIDER)
        keyGen.init(builder.build())
        keyGen.generateKey()
    }

    fun deleteKeysForAlias(keyAlias: String?) {
        val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
        val biometricAlias = Constants.biometricKeyAlias(keyAlias)
        val masterAlias = Constants.masterKeyAlias(keyAlias)

        runCatching { keyStore.deleteEntry(biometricAlias) }
        runCatching { keyStore.deleteEntry(masterAlias) }

        listOf(
            Constants.ecWrappedFilename(keyAlias),
            Constants.ecPubFilename(keyAlias)
        ).forEach { fileName ->
            val file = File(appContext.filesDir, fileName)
            if (file.exists()) {
                runCatching { file.writeBytes(ByteArray(file.length().toInt())) }
                file.delete()
            }
        }
    }

    fun deleteAllKeys() {
        val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }

        // Delete all plugin-managed keys from KeyStore
        val aliases = keyStore.aliases().toList()
        for (alias in aliases) {
            if (alias.startsWith(Constants.KEY_ALIAS_PREFIX) ||
                alias.startsWith(Constants.MASTER_KEY_ALIAS_PREFIX) ||
                alias == "biometric_key" ||
                alias == "biometric_master_key"
            ) {
                runCatching { keyStore.deleteEntry(alias) }
            }
        }

        // Delete all plugin-managed files
        appContext.filesDir.listFiles()?.forEach { file ->
            if (file.name.startsWith("biometric_ec_wrapped") ||
                file.name.startsWith("biometric_ec_pub")
            ) {
                runCatching { file.writeBytes(ByteArray(file.length().toInt())) }
                file.delete()
            }
        }
    }

    /**
     * Whether the signing key for [keyAlias] was created requiring user
     * authentication. Returns `true` (the safe default) when the key is missing
     * or its metadata cannot be read. Used to decide whether signing/decryption
     * must show a BiometricPrompt.
     */
    fun isUserAuthenticationRequired(keyAlias: String?): Boolean {
        val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
        val alias = Constants.biometricKeyAlias(keyAlias)
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: return true
        return try {
            val factory = KeyFactory.getInstance(entry.privateKey.algorithm, Constants.KEYSTORE_PROVIDER)
            val info = factory.getKeySpec(entry.privateKey, android.security.keystore.KeyInfo::class.java)
            (info as android.security.keystore.KeyInfo).isUserAuthenticationRequired
        } catch (e: Exception) {
            true
        }
    }

    fun keyExistsForAlias(keyAlias: String?): Boolean {
        val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
        return keyStore.containsAlias(Constants.biometricKeyAlias(keyAlias))
    }

    fun inferKeyModeFromKeystore(keyAlias: String?): KeyMode? {
        val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
        val alias = Constants.biometricKeyAlias(keyAlias)
        if (!keyStore.containsAlias(alias)) return null
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: return null
        val pub = entry.certificate.publicKey
        return when (pub) {
            is RSAPublicKey -> KeyMode.RSA
            is ECPublicKey -> {
                val wrappedExists = File(appContext.filesDir, Constants.ecWrappedFilename(keyAlias)).exists()
                if (wrappedExists) KeyMode.HYBRID_EC else KeyMode.EC_SIGN_ONLY
            }
            else -> null
        }
    }

    private fun configurePerOperationAuth(
        builder: KeyGenParameterSpec.Builder,
        useDeviceCredentials: Boolean
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val authType = if (useDeviceCredentials) {
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            } else {
                KeyProperties.AUTH_BIOMETRIC_STRONG
            }
            builder.setUserAuthenticationParameters(0, authType)
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
    }

    /**
     * Applies the caller's enrollment-invalidation choice to an auth-bound key.
     *
     * The setter is always called, never only for `true`: AndroidKeyStore's own
     * default is `true` (`mInvalidatedByBiometricEnrollment = true`), so skipping
     * the call for `false` left the platform default in place and silently
     * invalidated keys the caller asked to keep across enrollment changes.
     *
     * API 23 has no setter — those keys are always invalidated by the platform
     * when the enrolled fingerprints change.
     */
    private fun configureInvalidation(
        builder: KeyGenParameterSpec.Builder,
        invalidateOnEnrollment: Boolean
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(invalidateOnEnrollment)
        }
    }

    /**
     * Authorises SHA-1 as the OAEP MGF1 digest so the key matches the parameters decryption pins.
     *
     * Before API 35 a key carried no MGF1 authorisation at all and AndroidKeyStore always used
     * SHA-1. From API 35 the set is explicit, and a key that does not declare one falls back to a
     * platform default — the same undocumented behaviour this fix removes from the decrypt side.
     * Declaring SHA-1 records today's value rather than inheriting whatever the default becomes.
     * Best-effort: an unsupported builder call must not stop key creation.
     */
    private fun tryPinOaepMgf1Digest(builder: KeyGenParameterSpec.Builder) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            try {
                builder.setMgf1Digests(KeyProperties.DIGEST_SHA1)
            } catch (_: Throwable) {}
        }
    }

    private fun tryEnableStrongBox(builder: KeyGenParameterSpec.Builder) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        ) {
            try {
                builder.setIsStrongBoxBacked(true)
            } catch (_: Throwable) {}
        }
    }
}
