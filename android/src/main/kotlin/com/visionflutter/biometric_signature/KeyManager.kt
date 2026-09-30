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
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.KeyGenerator

/**
 * Attestation was requested but the device could not produce an attested key.
 *
 * [isTransient] is true when the keystore reported that retrying later is likely
 * to succeed (e.g. remotely provisioned attestation keys are not available yet).
 */
class KeyAttestationException(
    message: String,
    cause: Throwable? = null,
    val isTransient: Boolean = false
) : Exception(message, cause) {
    val errorCode: BiometricError
        get() = if (isTransient) BiometricError.NOT_AVAILABLE else BiometricError.NOT_SUPPORTED
}

fun attestationRequiresApi24Failure() =
    KeyAttestationException("Key attestation requires Android 7.0 (API 24) or newer")

/** Whether this mode accepts an unattested key after [failure]. */
fun AttestationMode.allowsFallback(failure: KeyAttestationException): Boolean = when (this) {
    AttestationMode.ENFORCE_ON_CHALLENGE -> false
    AttestationMode.ENFORCE_ON_CHALLENGE_IF_SUPPORTED -> !failure.isTransient
    AttestationMode.PREFERRED, AttestationMode.DISABLED -> true
}

/**
 * A generated keystore key plus its attestation chain (null when attestation
 * was not requested or fell back). [attestationFailure] is set when a
 * challenge was provided but the [AttestationMode] accepted an unattested key.
 */
data class GeneratedKey(
    val keyPair: KeyPair,
    val attestationCertChain: List<ByteArray>?,
    val attestationFailure: KeyAttestationException? = null
)

class KeyManager(private val appContext: Context, private val fileIO: FileIOHelper) {

    fun generateRsaKeyInKeyStore(
        keyAlias: String?,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enableDecryption: Boolean,
        requireAuthentication: Boolean,
        attestationChallenge: ByteArray? = null,
        attestationMode: AttestationMode = AttestationMode.ENFORCE_ON_CHALLENGE
    ): GeneratedKey {
        val purposes = if (enableDecryption) {
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
        } else {
            KeyProperties.PURPOSE_SIGN
        }

        val alias = Constants.biometricKeyAlias(keyAlias)

        fun specFor(useStrongBox: Boolean, challenge: ByteArray?): KeyGenParameterSpec {
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
            applyAttestationChallenge(builder, challenge)
            return builder.build()
        }

        return generateKeyPairWithOptionalAttestation(
            KeyProperties.KEY_ALGORITHM_RSA, alias, attestationChallenge, attestationMode, ::specFor
        )
    }

    fun generateEcKeyInKeyStore(
        keyAlias: String?,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        requireAuthentication: Boolean,
        attestationChallenge: ByteArray? = null,
        attestationMode: AttestationMode = AttestationMode.ENFORCE_ON_CHALLENGE
    ): GeneratedKey {
        val alias = Constants.biometricKeyAlias(keyAlias)

        fun specFor(useStrongBox: Boolean, challenge: ByteArray?): KeyGenParameterSpec {
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(requireAuthentication)

            if (requireAuthentication) {
                configurePerOperationAuth(builder, useDeviceCredentials)
                configureInvalidation(builder, invalidateOnEnrollment)
            }
            if (useStrongBox) tryEnableStrongBox(builder)
            applyAttestationChallenge(builder, challenge)
            return builder.build()
        }

        return generateKeyPairWithOptionalAttestation(
            KeyProperties.KEY_ALGORITHM_EC, alias, attestationChallenge, attestationMode, ::specFor
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
     * ProviderException) at generateKeyPair() time, where the builder-level
     * try/catch helpers cannot see them. A single TEE retry keeps the
     * attestation hardware-backed; it is skipped when StrongBox was never
     * requested, since it would only repeat the same (slow) TEE attempt. A
     * final failure removes any partial keystore entry so an unattested key
     * never shadows the alias.
     *
     * If [attestationMode] accepts the attestation failure, the key is
     * generated once more without a challenge, exactly as if none had been
     * provided, and the failure is reported alongside it.
     */
    private fun generateKeyPairWithOptionalAttestation(
        keyAlgorithm: String,
        alias: String,
        attestationChallenge: ByteArray?,
        attestationMode: AttestationMode,
        specFor: (useStrongBox: Boolean, challenge: ByteArray?) -> KeyGenParameterSpec
    ): GeneratedKey {
        fun generate(spec: KeyGenParameterSpec): KeyPair {
            val kpg = KeyPairGenerator.getInstance(keyAlgorithm, Constants.KEYSTORE_PROVIDER)
            kpg.initialize(spec)
            return kpg.generateKeyPair()
        }

        if (attestationChallenge == null) {
            return GeneratedKey(generate(specFor(true, null)), null)
        }

        return try {
            generateAttestedKeyPair(alias, attestationChallenge, ::generate, specFor)
        } catch (failure: KeyAttestationException) {
            if (!attestationMode.allowsFallback(failure)) throw failure
            GeneratedKey(generate(specFor(true, null)), null, failure)
        }
    }

    private fun generateAttestedKeyPair(
        alias: String,
        attestationChallenge: ByteArray,
        generate: (KeyGenParameterSpec) -> KeyPair,
        specFor: (useStrongBox: Boolean, challenge: ByteArray?) -> KeyGenParameterSpec
    ): GeneratedKey {
        // applyAttestationChallenge skips the setter below API 24, so without
        // this the keystore would generate a key only to reject it as unattested.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) throw attestationRequiresApi24Failure()

        val spec = specFor(true, attestationChallenge)
        val keyPair = try {
            generate(spec)
        } catch (firstFailure: Exception) {
            deleteEntryQuietly(alias)
            if (!isStrongBoxBacked(spec)) throw attestationFailure(firstFailure)
            try {
                generate(specFor(false, attestationChallenge))
            } catch (teeFailure: Exception) {
                deleteEntryQuietly(alias)
                throw attestationFailure(teeFailure)
            }
        }

        val chain = runCatching {
            val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
            attestationChainOf(keyStore.getCertificateChain(alias))
        }.getOrNull()
        if (chain == null) {
            // Never hand back an unattested key the caller believes is attested.
            deleteEntryQuietly(alias)
            throw KeyAttestationException("Keystore returned no key attestation certificate chain")
        }
        return GeneratedKey(keyPair, chain)
    }

    /**
     * The DER-encoded chain (leaf first) if [certificates] is a key attestation
     * chain: at least two certificates, with the Android key attestation
     * extension on the leaf. An unattested key's single self-signed keystore
     * certificate yields null. Never throws.
     */
    fun attestationChainOf(certificates: Array<out Certificate>?): List<ByteArray>? {
        if (certificates == null || certificates.size < 2) return null
        val leaf = certificates[0] as? X509Certificate ?: return null
        return try {
            if (leaf.getExtensionValue(Constants.KEY_ATTESTATION_EXTENSION_OID) == null) null
            else certificates.map { it.encoded }
        } catch (_: Exception) {
            null
        }
    }

    private fun isStrongBoxBacked(spec: KeyGenParameterSpec): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && spec.isStrongBoxBacked

    private fun deleteEntryQuietly(alias: String) {
        runCatching {
            KeyStore.getInstance(Constants.KEYSTORE_PROVIDER)
                .apply { load(null) }
                .deleteEntry(alias)
        }
    }

    /**
     * Classifies a key-generation failure that happened with a challenge set.
     *
     * Keystore failures surface as ProviderException (StrongBoxUnavailableException
     * included) wrapping an android.security.KeyStoreException, and become a
     * [KeyAttestationException]. Its message carries the whole cause chain
     * because the useful text — e.g. the remote key provisioning status — sits on
     * inner causes. Anything else (e.g. an invalid parameter) is returned
     * unchanged, so the generic error mapping classifies it exactly as it would
     * without a challenge.
     */
    private fun attestationFailure(e: Exception): Exception {
        if (e !is ProviderException) return e
        val causes = causeChain(e)
        val detail = causes.mapNotNull { it.message?.takeIf(String::isNotBlank) }
            .distinct()
            .joinToString(" -> ")
        return if (isTransientKeystoreFailure(causes)) {
            KeyAttestationException(
                "Key attestation is temporarily unavailable, retry later ($detail)",
                e,
                isTransient = true
            )
        } else {
            KeyAttestationException("Key attestation failed ($detail)", e)
        }
    }

    private fun causeChain(e: Throwable): List<Throwable> {
        val chain = mutableListOf<Throwable>()
        var current: Throwable? = e
        while (current != null && current !in chain) {
            chain.add(current)
            current = current.cause
        }
        return chain
    }

    /**
     * Whether the keystore marked the failure transient, i.e. retrying later is
     * likely to succeed (attestation keys still being provisioned, secure
     * hardware busy, ...). The flag is public API from Android 13 (API 33);
     * earlier versions don't expose it, so their failures count as permanent.
     */
    private fun isTransientKeystoreFailure(causes: List<Throwable>): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        for (cause in causes) {
            if (cause is android.security.KeyStoreException && cause.isTransientFailure) return true
        }
        return false
    }

    /**
     * Requests an attestation certificate chain for the key. Attested
     * generation rejects API 23 before building a spec; the guard here keeps
     * the setter call itself legal there.
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
