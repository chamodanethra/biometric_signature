package com.visionflutter.biometric_signature

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.StandardMethodCodec
import kotlinx.coroutines.*
import java.io.File
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * BiometricSignaturePlugin - Flutter plugin for biometric-protected cryptographic operations.
 *
 * Storage Architecture (mirrors iOS Keychain approach):
 * - Wrapped software EC private key is stored in the app's private files directory as a single binary file:
 *     [IV (12 bytes)] || [ciphertext]
 * - The associated public key (DER) is stored in a separate file
 *
 * Security Model:
 * - Files are private to the app (MODE_PRIVATE) and not world-readable
 * - The AES master key that encrypts the private key is Keystore-backed and requires biometric auth
 * - This mirrors iOS where encrypted RSA key is stored as kSecClassGenericPassword
 *
 * Security notes:
 * - Raw private key bytes are zeroed immediately after use
 * - Sensitive derived keys/bytes are zeroized where possible
 */
class BiometricSignaturePlugin : FlutterPlugin, MethodCallHandler, ActivityAware {

    // ==================== Constants ====================

    private companion object {
        const val CHANNEL_NAME = "biometric_signature"
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        // Key aliases in Keystore
        const val BIOMETRIC_KEY_ALIAS = "biometric_key"           // RSA or EC signing key
        const val MASTER_KEY_ALIAS = "biometric_master_key"       // AES wrapper for hybrid mode

        // File storage (mirrors iOS kSecClassGenericPassword storage)
        private const val EC_WRAPPED_FILENAME =
            "biometric_ec_wrapped.bin"  // contains iv||ciphertext
        private const val EC_PUB_FILENAME = "biometric_ec_pub.der"

        // ECIES constants
        const val EC_PUBKEY_SIZE = 65       // Uncompressed P-256: 0x04 || X(32) || Y(32)
        const val GCM_TAG_BITS = 128
        const val GCM_TAG_BYTES = 16
        const val AES_KEY_SIZE = 16         // AES-128 for ECIES
        const val GCM_IV_SIZE = 12
    }

    private object Errors {
        const val NO_ACTIVITY = "NO_ACTIVITY"
        const val AUTH_FAILED = "AUTH_FAILED"
        const val INVALID_PAYLOAD = "INVALID_PAYLOAD"
        const val KEY_NOT_FOUND = "KEY_NOT_FOUND"
        const val DECRYPTION_NOT_ENABLED = "DECRYPTION_NOT_ENABLED"
    }

    private enum class KeyMode {
        RSA,
        EC_SIGN_ONLY,
        HYBRID_EC
    }

    private enum class KeyFormat {
        BASE64, PEM, RAW, HEX;

        companion object {
            fun from(value: String?): KeyFormat = runCatching {
                valueOf(value?.uppercase(Locale.US) ?: "BASE64")
            }.getOrDefault(BASE64)
        }
    }

    private data class FormattedOutput(
        val value: Any,
        val format: KeyFormat,
        val pemLabel: String? = null
    )

    // ==================== Plugin State ====================
    private lateinit var channel: MethodChannel
    private lateinit var appContext: Context
    private var activity: FlutterFragmentActivity? = null

    private val pluginJob = SupervisorJob()
    private val pluginScope = CoroutineScope(Dispatchers.Main.immediate + pluginJob)

    // ==================== FlutterPlugin Lifecycle ====================
    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext
        val taskQueue = binding.binaryMessenger.makeBackgroundTaskQueue()
        channel = MethodChannel(
            binding.binaryMessenger,
            CHANNEL_NAME,
            StandardMethodCodec.INSTANCE,
            taskQueue
        )
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        pluginJob.cancel()
    }

    // ==================== ActivityAware ====================
    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FlutterFragmentActivity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onDetachedFromActivityForConfigChanges() = onDetachedFromActivity()
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) =
        onAttachedToActivity(binding)

    // ==================== Method Channel Handler ====================
    override fun onMethodCall(call: MethodCall, result: Result) {
        val act = activity ?: return result.error(
            Errors.NO_ACTIVITY,
            "Foreground activity required",
            null
        )

        pluginScope.launch {
            try {
                when (call.method) {
                    "createKeys" -> createKeys(call, result, act)
                    "createSignature" -> createSignature(call, result, act)
                    "decrypt" -> decrypt(call, result, act)
                    "deleteKeys" -> deleteKeys(result)
                    "biometricAuthAvailable" -> result.success(getBiometricAvailability())
                    "biometricKeyExists" -> result.success(checkKeyExists(call.arguments as? Boolean == true))
                    else -> result.notImplemented()
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Generic failures -> AUTH_FAILED
                result.error(Errors.AUTH_FAILED, e.message, null)
            }
        }
    }

    // ==================== Create Keys ====================
    private suspend fun createKeys(
        call: MethodCall,
        result: Result,
        activity: FlutterFragmentActivity
    ) {
        val args = call.arguments<Map<String, Any?>>() ?: emptyMap()
        val useEc = args.boolean("useEc")
        val enableDecryption = args.boolean("enableDecryption")
        val useDeviceCredentials = args.boolean("useDeviceCredentials")
        val invalidateOnEnrollment = args.boolean("setInvalidatedByBiometricEnrollment")
        val enforceBiometric = args.boolean("enforceBiometric")
        val keyFormat = KeyFormat.from(args["keyFormat"] as? String)

        // Determine mode
        val mode = when {
            !useEc -> KeyMode.RSA
            useEc && !enableDecryption -> KeyMode.EC_SIGN_ONLY
            else -> KeyMode.HYBRID_EC
        }

        when (mode) {
            KeyMode.RSA -> createRsaKeys(
                activity,
                result,
                useDeviceCredentials,
                invalidateOnEnrollment,
                enableDecryption,
                enforceBiometric,
                keyFormat
            )

            KeyMode.EC_SIGN_ONLY -> createEcSigningKeys(
                activity,
                result,
                useDeviceCredentials,
                invalidateOnEnrollment,
                enforceBiometric,
                keyFormat
            )

            KeyMode.HYBRID_EC -> createHybridEcKeys(
                activity,
                result,
                useDeviceCredentials,
                invalidateOnEnrollment,
                keyFormat,
                enforceBiometric
            )
        }
    }

    // ---------- RSA Mode ----------
    private suspend fun createRsaKeys(
        activity: FlutterFragmentActivity,
        result: Result,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enableDecryption: Boolean,
        enforceBiometric: Boolean,
        keyFormat: KeyFormat
    ) {
        if (enforceBiometric) {
            checkBiometricAvailability(activity, useDeviceCredentials)
            authenticate(
                activity,
                "Authenticate to create keys",
                null,
                "Cancel",
                useDeviceCredentials,
                null
            )
        }

        val keyPair = withContext(Dispatchers.IO) {
            deleteAllKeys()
            generateRsaKeyInKeyStore(useDeviceCredentials, invalidateOnEnrollment, enableDecryption)
        }

        val response = buildKeyResponse(keyPair.public, keyFormat, "RSA")
        result.success(response)
    }

    private fun generateRsaKeyInKeyStore(
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enableDecryption: Boolean
    ): KeyPair {
        val purposes = if (enableDecryption) {
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
        } else {
            KeyProperties.PURPOSE_SIGN
        }

        val builder = KeyGenParameterSpec.Builder(BIOMETRIC_KEY_ALIAS, purposes)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
            .setUserAuthenticationRequired(true)

        if (enableDecryption) {
            builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        }

        configurePerOperationAuth(builder, useDeviceCredentials)
        configureInvalidation(builder, invalidateOnEnrollment)
        tryEnableStrongBox(builder)

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER)
        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    // ---------- EC Signing Only Mode ----------
    private suspend fun createEcSigningKeys(
        activity: FlutterFragmentActivity,
        result: Result,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enforceBiometric: Boolean,
        keyFormat: KeyFormat
    ) {
        if (enforceBiometric) {
            checkBiometricAvailability(activity, useDeviceCredentials)
            authenticate(
                activity,
                "Authenticate to create keys",
                null,
                "Cancel",
                useDeviceCredentials,
                null
            )
        }

        val keyPair = withContext(Dispatchers.IO) {
            deleteAllKeys()
            generateEcKeyInKeyStore(useDeviceCredentials, invalidateOnEnrollment)
        }

        val response = buildKeyResponse(keyPair.public, keyFormat, "EC")
        result.success(response)
    }

    private fun generateEcKeyInKeyStore(
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean
    ): KeyPair {
        val builder = KeyGenParameterSpec.Builder(BIOMETRIC_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(true)

        configurePerOperationAuth(builder, useDeviceCredentials)
        configureInvalidation(builder, invalidateOnEnrollment)
        tryEnableStrongBox(builder)

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    // ---------- Hybrid EC Mode (Android) ----------
    // Generates hardware EC signing key (Keystore), AES master key (Keystore),
    // then creates a software EC keypair and encrypts the private key with the
    // master key. The wrapped blob is stored to app-private file.

    private suspend fun createHybridEcKeys(
        activity: FlutterFragmentActivity,
        result: Result,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        keyFormat: KeyFormat,
        enforceBiometric: Boolean
    ) {
        // Step 0: If requested, force biometric before key creation
        if (enforceBiometric) {
            checkBiometricAvailability(activity, useDeviceCredentials)
            // Authenticate with a no-crypto prompt for enforcement only
            authenticate(
                activity,
                "Authenticate to create keys",
                null,
                "Cancel",
                useDeviceCredentials,
                null
            )
        }

        // 1. Generate signing EC key and master AES key
        val signingKeyPair = withContext(Dispatchers.IO) {
            deleteAllKeys()
            // Generate EC signing key (hardware)
            val ecKeyPair = generateEcKeyInKeyStore(useDeviceCredentials, invalidateOnEnrollment)
            // Generate master AES key (hardware-backed secret) for wrapping
            generateMasterKey(useDeviceCredentials, invalidateOnEnrollment)
            ecKeyPair
        }

        // 2. Prepare an ENCRYPT cipher from master key — this operation requires biometric auth later
        val cipherForWrap = withContext(Dispatchers.IO) { getCipherForEncryption() }

        // 3. Ask user to authenticate to allow wrapping of the software private key
        checkBiometricAvailability(activity, useDeviceCredentials)
        val authResult = authenticate(
            activity,
            "Authenticate to create keys",
            null,
            "Cancel",
            useDeviceCredentials,
            BiometricPrompt.CryptoObject(cipherForWrap)
        )

        val authenticatedCipher = authResult.cryptoObject?.cipher
            ?: throw SecurityException("Authentication failed - no cipher returned")

        // 4. Generate software EC keypair and seal (encrypt) private key, store to files
        val (wrappedBlob, publicKeyBytes) = withContext(Dispatchers.IO) {
            generateAndSealDecryptionEcKeyLocal(authenticatedCipher)
        }

        // Persist wrapped blob and public key to files (app-private storage).
        // The wrappedBlob = IV || ciphertext
        writeFileAtomic(EC_WRAPPED_FILENAME, wrappedBlob)
        writeFileAtomic(EC_PUB_FILENAME, publicKeyBytes)

        // 5. Return response:
        //    For compatibility with previous responses, we return "publicKey" = the encryption public key (DER),
        //    and include separate "signingPublicKey" in response payload.
        val signingPubFormatted = formatOutput(signingKeyPair.public.encoded, keyFormat)
        val decryptionPubFormatted = formatOutput(publicKeyBytes, keyFormat)

        val response = hashMapOf<String, Any?>(
            "publicKey" to decryptionPubFormatted.value,
            "publicKeyFormat" to decryptionPubFormatted.format.name,
            "algorithm" to "EC",
            "keySize" to 256,
            "keyFormat" to keyFormat.name,
            "signingPublicKey" to signingPubFormatted.value,
            "signingPublicKeyFormat" to signingPubFormatted.format.name,
            "signingAlgorithm" to "EC",
            "signingKeySize" to 256,
            "hybridMode" to true
        )
        decryptionPubFormatted.pemLabel?.let { response["publicKeyPemLabel"] = it }
        signingPubFormatted.pemLabel?.let { response["signingPublicKeyPemLabel"] = it }

        result.success(response)
    }

    /**
     * Attempt to enable StrongBox (best-effort). If unavailable, leave builder as-is (TEE).
     */
    private fun tryEnableStrongBox(builder: KeyGenParameterSpec.Builder) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        ) {
            try {
                builder.setIsStrongBoxBacked(true)
            } catch (_: StrongBoxUnavailableException) {
                // Fallback silently (TEE)
            } catch (_: Throwable) {
                // Some devices may throw other runtime errors — ignore and fallback
            }
        }
    }

    /**
     * Generates an AES master key (256-bit) in AndroidKeyStore.
     * The key is created for per-operation (user-auth) usage.
     *
     * Note: We intentionally do NOT enable StrongBox for the master key to avoid
     * compatibility issues on some devices where StrongBox AES keys have limitations.
     */
    private fun generateMasterKey(useDeviceCredentials: Boolean, invalidateOnEnrollment: Boolean) {
        val builder = KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)

        configurePerOperationAuth(builder, useDeviceCredentials)
        configureInvalidation(builder, invalidateOnEnrollment)
        // Note: StrongBox intentionally not enabled for master key (compatibility)

        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        keyGen.init(builder.build())
        keyGen.generateKey()
    }

    /**
     * Returns an AES/GCM Cipher instance initialised for ENCRYPT_MODE with the
     * master key stored in AndroidKeyStore under MASTER_KEY_ALIAS.
     */
    private fun getCipherForEncryption(): Cipher {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val masterKey = keyStore.getKey(MASTER_KEY_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("Master key not found")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
        return cipher
    }

    /**
     * Returns an AES/GCM Cipher instance initialised for DECRYPT_MODE using the
     * master key and IV read from the wrapped file (first 12 bytes).
     *
     * Returns null if there is no wrapped file (i.e. decryption blob missing).
     */
    private fun getCipherForDecryption(): Cipher? {
        val wrapped = readFileIfExists(EC_WRAPPED_FILENAME) ?: return null
        if (wrapped.size < GCM_IV_SIZE + 1) return null

        val iv = wrapped.copyOfRange(0, GCM_IV_SIZE)
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val masterKey = keyStore.getKey(MASTER_KEY_ALIAS, null) as? SecretKey ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher
    }

    /**
     * Generate software EC P-256 keypair, encrypt (seal) the private key using the
     * provided (already authenticated) cipher, and return (wrappedBlob, publicKeyBytes).
     *
     * wrappedBlob layout: [IV (12 bytes)] || [ciphertext]
     *
     * Important: private key raw bytes are zeroed immediately after use.
     */
    private fun generateAndSealDecryptionEcKeyLocal(cipher: Cipher): Pair<ByteArray, ByteArray> {
        // Generate software EC keypair (P-256)
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val keyPair = kpg.generateKeyPair()

        val privateKeyBytes = keyPair.private.encoded
        val publicKeyBytes = keyPair.public.encoded

        try {
            val encrypted = cipher.doFinal(privateKeyBytes)
            val iv = cipher.iv ?: throw IllegalStateException("Cipher IV missing")
            // Build wrapped = iv || encrypted
            val wrapped = ByteArray(iv.size + encrypted.size)
            System.arraycopy(iv, 0, wrapped, 0, iv.size)
            System.arraycopy(encrypted, 0, wrapped, iv.size, encrypted.size)
            return Pair(wrapped, publicKeyBytes)
        } finally {
            // Zero raw private key bytes ASAP
            privateKeyBytes.fill(0)
        }
    }

    // ==================== Create Signature ====================
    private suspend fun createSignature(
        call: MethodCall,
        result: Result,
        activity: FlutterFragmentActivity
    ) {
        val args = call.arguments<Map<String, Any?>>() ?: emptyMap()
        val payload = args["payload"] as? String

        if (payload.isNullOrBlank()) {
            return result.error(Errors.INVALID_PAYLOAD, "Payload is required", null)
        }

        val mode = inferKeyModeFromKeystore() ?: return result.error(
            Errors.KEY_NOT_FOUND,
            "Signing key not found",
            null
        )
        val allowDeviceCredentials = args.boolean("allowDeviceCredentials")
        val keyFormat = KeyFormat.from(args["keyFormat"] as? String)

        // All modes use the KeyStore key for signing
        val (signature, cryptoObject) = withContext(Dispatchers.IO) {
            prepareSignature(mode)
        }

        checkBiometricAvailability(activity, allowDeviceCredentials)

        val authResult = authenticate(
            activity,
            args["promptMessage"] as? String ?: "Authenticate",
            args["subtitle"] as? String,
            args["cancelButtonText"] as? String ?: "Cancel",
            allowDeviceCredentials,
            cryptoObject
        )

        val signatureBytes = withContext(Dispatchers.IO) {
            val sig = authResult.cryptoObject?.signature ?: signature
            sig.update(payload.toByteArray(Charsets.UTF_8))
            sig.sign()
        }

        val publicKey = getSigningPublicKey()
        val response = buildSignatureResponse(signatureBytes, publicKey, keyFormat, mode)
        result.success(response)
    }

    private fun prepareSignature(mode: KeyMode): Pair<Signature, BiometricPrompt.CryptoObject?> {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val entry = keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Signing key not found")

        val algorithm = when (mode) {
            KeyMode.RSA -> "SHA256withRSA"
            else -> "SHA256withECDSA"
        }

        val signature = Signature.getInstance(algorithm)
        return try {
            signature.initSign(entry.privateKey)
            Pair(signature, BiometricPrompt.CryptoObject(signature))
        } catch (e: Exception) {
            // Fallback to non-crypto prompt: signature object returned but cryptoObject null
            Pair(signature, null)
        }
    }

    private fun getSigningPublicKey(): PublicKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val entry = keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Signing key not found")
        return entry.certificate.publicKey
    }

    // ==================== Decrypt ====================
    private suspend fun decrypt(
        call: MethodCall,
        result: Result,
        activity: FlutterFragmentActivity
    ) {
        val args = call.arguments<Map<String, Any?>>() ?: emptyMap()
        val payload = args["payload"] as? String

        if (payload.isNullOrBlank()) {
            return result.error(Errors.INVALID_PAYLOAD, "Payload is required", null)
        }

        val mode = inferKeyModeFromKeystore()
            ?: return result.error(Errors.KEY_NOT_FOUND, "Keys not found", null)

        if (mode == KeyMode.EC_SIGN_ONLY) {
            return result.error(
                Errors.DECRYPTION_NOT_ENABLED,
                "Decryption not enabled for EC signing-only mode",
                null
            )
        }

        val allowDeviceCredentials = args.boolean("allowDeviceCredentials")
        when (mode) {
            KeyMode.RSA -> decryptRsa(activity, result, payload, args, allowDeviceCredentials)
            KeyMode.HYBRID_EC -> decryptHybridEc(
                activity,
                result,
                payload,
                args,
                allowDeviceCredentials
            )

            else -> result.error(Errors.DECRYPTION_NOT_ENABLED, "Unsupported decryption mode", null)
        }
    }

    private suspend fun decryptRsa(
        activity: FlutterFragmentActivity,
        result: Result,
        payload: String,
        args: Map<String, Any?>,
        allowDeviceCredentials: Boolean
    ) {
        val cipher = withContext(Dispatchers.IO) {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val entry = keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                ?: throw IllegalStateException("RSA key not found")

            Cipher.getInstance("RSA/ECB/PKCS1Padding").apply {
                init(Cipher.DECRYPT_MODE, entry.privateKey)
            }
        }

        checkBiometricAvailability(activity, allowDeviceCredentials)

        val authResult = authenticate(
            activity,
            args["promptMessage"] as? String ?: "Authenticate",
            args["subtitle"] as? String,
            args["cancelButtonText"] as? String ?: "Cancel",
            allowDeviceCredentials,
            BiometricPrompt.CryptoObject(cipher)
        )

        val decrypted = withContext(Dispatchers.IO) {
            val authenticatedCipher = authResult.cryptoObject?.cipher
                ?: throw SecurityException("Authentication failed - no cipher returned")
            val encryptedBytes = Base64.decode(payload, Base64.NO_WRAP)
            authenticatedCipher.doFinal(encryptedBytes)
        }

        result.success(mapOf("decryptedData" to String(decrypted, Charsets.UTF_8)))
    }

    private suspend fun decryptHybridEc(
        activity: FlutterFragmentActivity,
        result: Result,
        payload: String,
        args: Map<String, Any?>,
        allowDeviceCredentials: Boolean
    ) {
        // Prepare cipher to unwrap EC key from wrapped file
        val cipher = withContext(Dispatchers.IO) {
            getCipherForDecryption()
        } ?: return result.error(Errors.KEY_NOT_FOUND, "Decryption keys not found", null)

        checkBiometricAvailability(activity, allowDeviceCredentials)

        val authResult = authenticate(
            activity,
            args["promptMessage"] as? String ?: "Authenticate",
            args["subtitle"] as? String,
            args["cancelButtonText"] as? String ?: "Cancel",
            allowDeviceCredentials,
            BiometricPrompt.CryptoObject(cipher)
        )

        val decrypted = withContext(Dispatchers.IO) {
            val authenticatedCipher = authResult.cryptoObject?.cipher
                ?: throw SecurityException("Authentication failed - no cipher returned")
            performEciesDecryption(authenticatedCipher, payload)
        }

        result.success(mapOf("decryptedData" to decrypted))
    }

    /**
     * ECIES decryption implementation that un-wraps the encrypted EC private key using the authenticated
     * AES master key (cipher). Sensitive material is zeroized ASAP.
     *
     * Payload format: [ephemeral_public_key || ciphertext || auth_tag]  (all base64-encoded input)
     */
    private fun performEciesDecryption(unwrapCipher: Cipher, payloadBase64: String): String {
        // 1. Read wrapped blob file
        val wrapped = readFileIfExists(EC_WRAPPED_FILENAME)
            ?: throw IllegalStateException("Encrypted EC key not found")
        if (wrapped.size < GCM_IV_SIZE + 1) throw IllegalStateException("Malformed wrapped blob")

        // Split wrapped: iv || encryptedPrivateKey
        val encryptedKey = wrapped.copyOfRange(GCM_IV_SIZE, wrapped.size)

        var privateKeyBytes: ByteArray? = null
        try {
            // decrypt using the provided authenticated cipher
            privateKeyBytes = unwrapCipher.doFinal(encryptedKey)

            val privateKey: PrivateKey = KeyFactory.getInstance("EC")
                .generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

            // 2. Parse ECIES payload
            val data = Base64.decode(payloadBase64, Base64.NO_WRAP)
            require(data.size >= EC_PUBKEY_SIZE + GCM_TAG_BYTES) {
                "Invalid ECIES payload: too short (${data.size} bytes)"
            }

            val ephemeralKeyBytes = data.copyOfRange(0, EC_PUBKEY_SIZE)
            require(ephemeralKeyBytes[0] == 0x04.toByte()) {
                "Invalid ephemeral key: expected uncompressed (0x04)"
            }

            val ciphertextWithTag = data.copyOfRange(EC_PUBKEY_SIZE, data.size)

            // 3. Reconstruct ephemeral public key
            val ephemeralPubKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(createX509ForRawEcPub(ephemeralKeyBytes)))

            // 4. ECDH
            val sharedSecret: ByteArray = KeyAgreement.getInstance("ECDH").run {
                init(privateKey)
                doPhase(ephemeralPubKey, true)
                generateSecret()
            }

            // 5. KDF -> AES key + IV
            val derived: ByteArray = try {
                kdfX963(sharedSecret, AES_KEY_SIZE + GCM_IV_SIZE)
            } finally {
                sharedSecret.fill(0)
            }

            val aesKeyBytes = derived.copyOfRange(0, AES_KEY_SIZE)
            val gcmIv = derived.copyOfRange(AES_KEY_SIZE, AES_KEY_SIZE + GCM_IV_SIZE)
            derived.fill(0)

            // 6. AES-GCM decrypt
            try {
                val aesKey = SecretKeySpec(aesKeyBytes, "AES")
                val decrypted = Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_BITS, gcmIv))
                    doFinal(ciphertextWithTag)
                }
                return String(decrypted, Charsets.UTF_8)
            } finally {
                aesKeyBytes.fill(0)
                gcmIv.fill(0)
            }
        } finally {
            // Zero raw private key bytes
            privateKeyBytes?.fill(0)
            encryptedKey.fill(0)
        }
    }

    private fun createX509ForRawEcPub(raw: ByteArray): ByteArray {
        // X.509 header for P-256 followed by raw uncompressed point
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

    // ==================== Delete Keys ====================
    private suspend fun deleteKeys(result: Result) {
        withContext(Dispatchers.IO) { deleteAllKeys() }
        result.success(true)
    }

    private fun deleteAllKeys() {
        // Delete Keystore entries
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        runCatching { keyStore.deleteEntry(BIOMETRIC_KEY_ALIAS) }
        runCatching { keyStore.deleteEntry(MASTER_KEY_ALIAS) }

        // Delete files with secure overwrite
        listOf(EC_WRAPPED_FILENAME, EC_PUB_FILENAME).forEach { fileName ->
            val file = File(appContext.filesDir, fileName)
            if (file.exists()) {
                // Overwrite with zeros before deletion
                runCatching {
                    file.writeBytes(ByteArray(file.length().toInt()))
                }
                file.delete()
            }
        }
    }

    // ==================== Biometric Availability ====================
    private fun getBiometricAvailability(): String {
        val act = activity ?: return "none, NO_ACTIVITY"
        val manager = BiometricManager.from(act)
        val canAuth = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        return if (canAuth == BiometricManager.BIOMETRIC_SUCCESS) {
            detectBiometricType()
        } else {
            "none, ${biometricErrorName(canAuth)}"
        }
    }

    private fun detectBiometricType(): String {
        var identifiedFingerprint = false
        val pm = appContext.packageManager

        if (pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            val fm = appContext.getSystemService(FingerprintManager::class.java)
            val enrolled = try {
                fm?.hasEnrolledFingerprints() == true
            } catch (_: SecurityException) {
                true
            }
            identifiedFingerprint = fm?.isHardwareDetected == true && enrolled
        }

        val otherString = listOf("face", "iris", ",")
        val otherBiometrics = otherString.filter {
            BiometricManager.from(activity!!)
                .getStrings(BiometricManager.Authenticators.BIOMETRIC_STRONG)?.buttonLabel
                .toString().contains(it, ignoreCase = true)
        }

        return if (identifiedFingerprint) {
            if (otherBiometrics.isEmpty()) "fingerprint" else "biometric"
        } else {
            if (otherBiometrics.size == 1 && otherBiometrics[0] != ",") otherBiometrics[0] else "biometric"
        }
    }


    private fun biometricErrorName(code: Int) = when (code) {
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "BIOMETRIC_ERROR_NO_HARDWARE"
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "BIOMETRIC_ERROR_HW_UNAVAILABLE"
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "BIOMETRIC_ERROR_NONE_ENROLLED"
        BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED"
        BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> "BIOMETRIC_ERROR_UNSUPPORTED"
        BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> "BIOMETRIC_STATUS_UNKNOWN"
        else -> "UNKNOWN_ERROR"
    }

    // ==================== Key Exists ====================
    private fun checkKeyExists(checkValidity: Boolean): Boolean {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)) return false
        if (!checkValidity) return true

        return runCatching {
            val entry = keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            entry != null
        }.getOrDefault(false)
    }

    /**
     * Infer key mode from Keystore and presence of wrapped blob file.
     */
    private fun inferKeyModeFromKeystore(): KeyMode? {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)) return null

        val entry =
            keyStore.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return null
        val pub = entry.certificate.publicKey

        return when (pub) {
            is RSAPublicKey -> KeyMode.RSA
            is ECPublicKey -> {
                val wrappedExists = File(appContext.filesDir, EC_WRAPPED_FILENAME).exists()
                if (wrappedExists) KeyMode.HYBRID_EC else KeyMode.EC_SIGN_ONLY
            }
            else -> null
        }
    }

    // ==================== Authentication ====================
    private suspend fun checkBiometricAvailability(
        activity: FragmentActivity,
        allowDeviceCredentials: Boolean
    ) {
        val authenticators = getAuthenticators(allowDeviceCredentials)
        val canAuth = BiometricManager.from(activity).canAuthenticate(authenticators)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            throw SecurityException("Biometric not available (code: $canAuth)")
        }
    }

    private suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String?,
        cancelText: String,
        allowDeviceCredentials: Boolean,
        cryptoObject: BiometricPrompt.CryptoObject?
    ): BiometricPrompt.AuthenticationResult = suspendCancellableCoroutine { cont ->

        val authenticators = getAuthenticators(allowDeviceCredentials)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (cont.isActive) cont.resume(result)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (cont.isActive) cont.resumeWithException(SecurityException("$errString (code: $errorCode)"))
            }

            override fun onAuthenticationFailed() { /* User can retry */
            }
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(authenticators)
            .apply {
                if (!subtitle.isNullOrBlank()) setSubtitle(subtitle)
                if (!(allowDeviceCredentials && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)) {
                    setNegativeButtonText(cancelText)
                }
            }
            .build()

        runCatching {
            activity.setTheme(androidx.appcompat.R.style.Theme_AppCompat_Light_DarkActionBar)
            val prompt =
                BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            if (cryptoObject != null) {
                prompt.authenticate(promptInfo, cryptoObject)
            } else {
                prompt.authenticate(promptInfo)
            }
        }.onFailure { e ->
            if (cont.isActive) cont.resumeWithException(e)
        }
    }

    private fun getAuthenticators(allowDeviceCredentials: Boolean): Int {
        return if (allowDeviceCredentials && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        }
    }

    // ==================== Key Generation Helpers ====================
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

    private fun configureInvalidation(
        builder: KeyGenParameterSpec.Builder,
        invalidateOnEnrollment: Boolean
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && invalidateOnEnrollment) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }
    }

    // ==================== Response Builders ====================

    private fun buildKeyResponse(
        publicKey: PublicKey,
        format: KeyFormat,
        algorithm: String
    ): Map<String, Any?> {
        val formatted = formatOutput(publicKey.encoded, format)
        val keySize = when (publicKey) {
            is RSAPublicKey -> publicKey.modulus.bitLength()
            is ECPublicKey -> publicKey.params.order.bitLength()
            else -> 0
        }

        return hashMapOf(
            "publicKey" to formatted.value,
            "publicKeyFormat" to formatted.format.name,
            "algorithm" to algorithm,
            "keySize" to keySize,
            "keyFormat" to format.name
        ).apply {
            formatted.pemLabel?.let { put("publicKeyPemLabel", it) }
        }
    }

    private fun buildSignatureResponse(
        signatureBytes: ByteArray,
        publicKey: PublicKey,
        format: KeyFormat,
        mode: KeyMode
    ): Map<String, Any?> {
        val sigFormatted = formatOutput(signatureBytes, format, "SIGNATURE")
        val pubFormatted = formatOutput(publicKey.encoded, format)

        val algorithm = if (mode == KeyMode.RSA) "RSA" else "EC"
        val keySize = when (publicKey) {
            is RSAPublicKey -> publicKey.modulus.bitLength()
            is ECPublicKey -> publicKey.params.order.bitLength()
            else -> 0
        }

        return hashMapOf(
            "signature" to sigFormatted.value,
            "signatureFormat" to sigFormatted.format.name,
            "publicKey" to pubFormatted.value,
            "publicKeyFormat" to pubFormatted.format.name,
            "algorithm" to algorithm,
            "keySize" to keySize,
            "timestamp" to isoTimestamp()
        ).apply {
            sigFormatted.pemLabel?.let { put("signaturePemLabel", it) }
            pubFormatted.pemLabel?.let { put("publicKeyPemLabel", it) }
        }
    }

    // ==================== Formatting ====================
    private fun formatOutput(
        bytes: ByteArray,
        format: KeyFormat,
        label: String = "PUBLIC KEY"
    ): FormattedOutput =
        when (format) {
            KeyFormat.BASE64 -> FormattedOutput(bytes.toBase64(), format)
            KeyFormat.HEX -> FormattedOutput(bytes.joinToString("") { "%02x".format(it) }, format)
            KeyFormat.RAW -> FormattedOutput(bytes, format)
            KeyFormat.PEM -> FormattedOutput(
                "-----BEGIN $label-----\n${
                    bytes.toBase64().chunked(64).joinToString("\n")
                }\n-----END $label-----",
                format,
                label
            )
        }

    private fun isoTimestamp(): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        .apply { timeZone = TimeZone.getTimeZone("UTC") }
        .format(Date())

    // ==================== I/O Helpers ====================

    private fun writeFileAtomic(fileName: String, data: ByteArray) {
        File(appContext.filesDir, fileName).outputStream().use { it.write(data) }
    }

    private fun readFileIfExists(fileName: String): ByteArray? {
        val file = File(appContext.filesDir, fileName)
        return if (!file.exists()) null else file.readBytes()
    }

    // ==================== Extensions ====================

    private fun ByteArray.toBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP)

    private fun Map<String, Any?>.boolean(key: String): Boolean = when (val v = this[key]) {
        is Boolean -> v
        is String -> v.equals("true", ignoreCase = true)
        else -> false
    }
}
