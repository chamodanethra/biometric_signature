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
import java.security.ProviderException
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.concurrent.CancellationException
import javax.crypto.KeyGenerator

/** Attestation was requested but the device could not produce an attested key. */
class KeyAttestationException(message: String, cause: Throwable? = null) :
    Exception(message, cause)

/** A generated keystore key plus its attestation chain (null when attestation was not requested). */
data class GeneratedKey(
    val keyPair: KeyPair,
    val attestationCertChain: List<ByteArray>?
)

class KeyManager(private val appContext: Context, private val fileIO: FileIOHelper) {

    fun generateRsaKeyInKeyStore(
        keyAlias: String?,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enableDecryption: Boolean,
        requireAuthentication: Boolean,
        attestationChallenge: ByteArray? = null
    ): GeneratedKey {
        val purposes = if (enableDecryption) {
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
        } else {
            KeyProperties.PURPOSE_SIGN
        }

        val alias = Constants.biometricKeyAlias(keyAlias)

        fun specFor(useStrongBox: Boolean): KeyGenParameterSpec {
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
            if (useStrongBox) tryEnableStrongBox(builder)
            applyAttestationChallenge(builder, attestationChallenge)
            return builder.build()
        }

        return generateKeyPairWithOptionalAttestation(
            KeyProperties.KEY_ALGORITHM_RSA, alias, attestationChallenge, ::specFor
        )
    }

    fun generateEcKeyInKeyStore(
        keyAlias: String?,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        requireAuthentication: Boolean,
        attestationChallenge: ByteArray? = null
    ): GeneratedKey {
        val alias = Constants.biometricKeyAlias(keyAlias)

        fun specFor(useStrongBox: Boolean): KeyGenParameterSpec {
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(requireAuthentication)

            if (requireAuthentication) {
                configurePerOperationAuth(builder, useDeviceCredentials)
                configureInvalidation(builder, invalidateOnEnrollment)
            }
            if (useStrongBox) tryEnableStrongBox(builder)
            applyAttestationChallenge(builder, attestationChallenge)
            return builder.build()
        }

        return generateKeyPairWithOptionalAttestation(
            KeyProperties.KEY_ALGORITHM_EC, alias, attestationChallenge, ::specFor
        )
    }

    /**
     * Runs key generation, adding attestation-specific failure handling.
     *
     * Without a challenge the behavior is identical to the pre-attestation
     * code path: a single attempt with StrongBox enabled best-effort, any
     * failure propagating unchanged to the caller.
     *
     * With a challenge, failures are handled deliberately because attestation
     * is an explicit opt-in that must not silently degrade: StrongBox devices
     * can fail attestation-chain generation (StrongBoxUnavailableException,
     * ProviderException "Failed to generate attestation certificate chain")
     * at generateKeyPair() time, where the builder-level try/catch helpers
     * cannot see them. A single TEE retry keeps the attestation
     * hardware-backed; a final failure removes any partial keystore entry so
     * an unattested key never shadows the alias.
     */
    private fun generateKeyPairWithOptionalAttestation(
        keyAlgorithm: String,
        alias: String,
        attestationChallenge: ByteArray?,
        specFor: (useStrongBox: Boolean) -> KeyGenParameterSpec
    ): GeneratedKey {
        fun attempt(useStrongBox: Boolean): KeyPair {
            val kpg = KeyPairGenerator.getInstance(keyAlgorithm, Constants.KEYSTORE_PROVIDER)
            kpg.initialize(specFor(useStrongBox))
            return kpg.generateKeyPair()
        }

        fun deleteEntryQuietly() {
            runCatching {
                KeyStore.getInstance(Constants.KEYSTORE_PROVIDER)
                    .apply { load(null) }
                    .deleteEntry(alias)
            }
        }

        if (attestationChallenge == null) {
            return GeneratedKey(attempt(useStrongBox = true), null)
        }

        val keyPair = try {
            attempt(useStrongBox = true)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (strongBoxFailure: Exception) {
            deleteEntryQuietly()
            try {
                attempt(useStrongBox = false)
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (teeFailure: Exception) {
                deleteEntryQuietly()
                if (teeFailure is ProviderException) {
                    // Keystore/attestation provider failure ("Failed to
                    // generate attestation certificate chain",
                    // StrongBoxUnavailableException, ...).
                    throw KeyAttestationException(
                        "Failed to generate a hardware-attested key: ${teeFailure.message}",
                        teeFailure
                    )
                }
                // Not an attestation-provider failure (e.g. an invalid
                // parameter): let the generic error mapping classify it the
                // same way it would without a challenge, instead of
                // mislabelling it notSupported.
                throw teeFailure
            }
        }

        val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
        val certificates = keyStore.getCertificateChain(alias)
        if (certificates == null || certificates.size < 2) {
            // A single self-signed certificate is not an attestation chain —
            // never hand back an unattested key the caller believes is attested.
            deleteEntryQuietly()
            throw KeyAttestationException("Keystore returned no attestation certificate chain")
        }
        return GeneratedKey(keyPair, certificates.map { it.encoded })
    }

    /**
     * Requests an attestation certificate chain for the key. The plugin
     * pre-validates API 24 and rejects older devices; the guard here keeps
     * the setter call itself legal on API 23.
     */
    private fun applyAttestationChallenge(
        builder: KeyGenParameterSpec.Builder,
        attestationChallenge: ByteArray?
    ) {
        if (attestationChallenge != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setAttestationChallenge(attestationChallenge)
        }
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
