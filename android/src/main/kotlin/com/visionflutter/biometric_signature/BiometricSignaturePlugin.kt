package com.visionflutter.biometric_signature

import android.content.Context
import android.os.Build
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.biometric.BiometricPrompt
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import kotlinx.coroutines.*
import java.security.*
import kotlin.coroutines.cancellation.CancellationException
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

class BiometricSignaturePlugin : FlutterPlugin, BiometricSignatureApi, ActivityAware {

    private lateinit var appContext: Context

    @Volatile
    private var activity: FlutterFragmentActivity? = null

    private val pluginJob = SupervisorJob()
    private val pluginScope = CoroutineScope(Dispatchers.Main.immediate + pluginJob)

    private lateinit var fileIOHelper: FileIOHelper
    private lateinit var keyManager: KeyManager
    private lateinit var cryptoOperations: CryptoOperations
    private lateinit var biometricPromptHelper: BiometricPromptHelper

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext

        fileIOHelper = FileIOHelper(appContext)
        keyManager = KeyManager(appContext, fileIOHelper)
        cryptoOperations = CryptoOperations(fileIOHelper)
        biometricPromptHelper = BiometricPromptHelper(appContext)

        BiometricSignatureApi.setUp(binding.binaryMessenger, this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        BiometricSignatureApi.setUp(binding.binaryMessenger, null)
        pluginJob.cancel()
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FlutterFragmentActivity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onDetachedFromActivityForConfigChanges() = onDetachedFromActivity()
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) =
        onAttachedToActivity(binding)

    // ==================== BiometricSignatureApi Implementation ====================

    override fun biometricAuthAvailable(callback: (Result<BiometricAvailability>) -> Unit) {
        val act = activity
        if (act == null) {
            callback(
                Result.success(
                    BiometricAvailability(
                        canAuthenticate = false,
                        hasEnrolledBiometrics = false,
                        availableBiometrics = emptyList(),
                        reason = "NO_ACTIVITY"
                    )
                )
            )
            return
        }

        val manager = androidx.biometric.BiometricManager.from(act)
        val canAuth = manager.canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)

        val canAuthenticate = canAuth == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
        val hasEnrolledBiometrics = canAuth != androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED &&
                canAuth != androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE &&
                canAuth != androidx.biometric.BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE

        val biometricTypes = biometricPromptHelper.detectBiometricTypes()
        val reason = if (!canAuthenticate) ErrorMapper.biometricErrorName(canAuth) else null

        callback(
            Result.success(
                BiometricAvailability(
                    canAuthenticate = canAuthenticate,
                    hasEnrolledBiometrics = hasEnrolledBiometrics,
                    availableBiometrics = biometricTypes,
                    reason = reason
                )
            )
        )
    }

    override fun createKeys(
        keyAlias: String?,
        config: CreateKeysConfig?,
        keyFormat: KeyFormat,
        promptMessage: String?,
        callback: (Result<KeyCreationResult>) -> Unit
    ) {
        val act = activity
        if (act == null) {
            callback(
                Result.success(
                    KeyCreationResult(
                        code = BiometricError.UNKNOWN,
                        error = "Foreground activity required"
                    )
                )
            )
            return
        }

        pluginScope.launch {
            try {
                // Checked before the attestation pre-checks below so an existing
                // key reports keyAlreadyExists rather than an attestation error.
                val failIfExists = config?.failIfExists ?: false

                if (failIfExists) {
                    val exists = withContext(Dispatchers.IO) { keyManager.keyExistsForAlias(keyAlias) }
                    if (exists) {
                        callback(
                            Result.success(
                                KeyCreationResult(
                                    code = BiometricError.KEY_ALREADY_EXISTS,
                                    error = "A key with alias '${keyAlias ?: "default"}' already exists"
                                )
                            )
                        )
                        return@launch
                    }
                }

                // Attestation is an explicit security opt-in: invalid requests
                // hard-fail before any key material is touched, in every mode
                // but DISABLED, which ignores the challenge altogether.
                val attestationMode = config?.attestationMode ?: AttestationMode.ENFORCE_ON_CHALLENGE
                val attestationChallenge = config?.attestationChallenge
                    ?.takeIf { attestationMode != AttestationMode.DISABLED }
                if (attestationChallenge != null) {
                    if (attestationChallenge.isEmpty() || attestationChallenge.size > 128) {
                        callback(
                            Result.success(
                                KeyCreationResult(
                                    code = BiometricError.INVALID_INPUT,
                                    error = "attestationChallenge must be between 1 and 128 bytes"
                                )
                            )
                        )
                        return@launch
                    }
                    // Modes that fall back are handled by KeyManager after the
                    // prompt, like any other attestation failure.
                    val unsupported = attestationRequiresApi24Failure()
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N &&
                        !attestationMode.allowsFallback(unsupported)
                    ) {
                        callback(
                            Result.success(
                                KeyCreationResult(code = unsupported.errorCode, error = unsupported.message)
                            )
                        )
                        return@launch
                    }
                }

                val useDeviceCredentials = config?.useDeviceCredentials ?: false
                val enableDecryption = config?.enableDecryption ?: false
                // Defaults to `true` on every platform, matching AndroidKeyStore's
                // own default for auth-bound keys.
                val invalidateOnEnrollment = config?.setInvalidatedByBiometricEnrollment ?: true
                val signatureType = config?.signatureType ?: SignatureType.RSA
                val requireAuthentication = config?.requireAuthentication ?: true
                // A non-interactive key (requireAuthentication == false) must never
                // prompt, not even at creation time, regardless of enforceBiometric.
                val enforceBiometric = (config?.enforceBiometric ?: false) && requireAuthentication

                val mode = when (signatureType) {
                    SignatureType.RSA -> KeyMode.RSA
                    SignatureType.ECDSA -> if (enableDecryption) KeyMode.HYBRID_EC else KeyMode.EC_SIGN_ONLY
                }

                val prompt = promptMessage ?: "Authenticate to create keys"
                val promptSubtitle = config?.promptSubtitle
                val promptDescription = config?.promptDescription
                val cancelButtonText = config?.cancelButtonText ?: "Cancel"

                when (mode) {
                    KeyMode.RSA -> createRsaKeys(
                        act,
                        keyAlias,
                        callback,
                        useDeviceCredentials,
                        invalidateOnEnrollment,
                        enableDecryption,
                        enforceBiometric,
                        keyFormat,
                        prompt,
                        promptSubtitle,
                        promptDescription,
                        cancelButtonText,
                        requireAuthentication,
                        attestationChallenge,
                        attestationMode
                    )

                    KeyMode.EC_SIGN_ONLY -> createEcSigningKeys(
                        act,
                        keyAlias,
                        callback,
                        useDeviceCredentials,
                        invalidateOnEnrollment,
                        enforceBiometric,
                        keyFormat,
                        prompt,
                        promptSubtitle,
                        promptDescription,
                        cancelButtonText,
                        requireAuthentication,
                        attestationChallenge,
                        attestationMode
                    )

                    KeyMode.HYBRID_EC -> createHybridEcKeys(
                        act,
                        keyAlias,
                        callback,
                        useDeviceCredentials,
                        invalidateOnEnrollment,
                        keyFormat,
                        enforceBiometric,
                        prompt,
                        promptSubtitle,
                        promptDescription,
                        cancelButtonText,
                        requireAuthentication,
                        attestationChallenge,
                        attestationMode
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: KeyAttestationException) {
                // Typed at the one call path that can produce it, instead of a
                // global ProviderException mapping that would reclassify
                // unrelated keystore errors in the sign/decrypt paths.
                // Transient failures (e.g. attestation keys not provisioned yet)
                // are retryable, so they must not read as "never supported".
                callback(
                    Result.success(
                        KeyCreationResult(
                            code = e.errorCode,
                            error = e.message
                        )
                    )
                )
            } catch (e: Exception) {
                callback(
                    Result.success(
                        KeyCreationResult(
                            code = ErrorMapper.mapToBiometricError(e),
                            error = ErrorMapper.safeErrorMessage(e)
                        )
                    )
                )
            }
        }
    }

    private suspend fun createRsaKeys(
        activity: FlutterFragmentActivity,
        keyAlias: String?,
        callback: (Result<KeyCreationResult>) -> Unit,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enableDecryption: Boolean,
        enforceBiometric: Boolean,
        keyFormat: KeyFormat,
        promptMessage: String,
        promptSubtitle: String?,
        promptDescription: String?,
        cancelButtonText: String,
        requireAuthentication: Boolean,
        attestationChallenge: ByteArray?,
        attestationMode: AttestationMode
    ) {
        var authType: AuthenticationType? = null
        if (enforceBiometric) {
            biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
            val outcome = biometricPromptHelper.authenticate(
                activity, promptMessage, promptSubtitle, promptDescription, cancelButtonText,
                useDeviceCredentials, null
            )
            authType = outcome.authenticationType
        }

        val generated = withContext(Dispatchers.IO) {
            keyManager.deleteKeysForAlias(keyAlias)
            keyManager.generateRsaKeyInKeyStore(
                keyAlias,
                useDeviceCredentials,
                invalidateOnEnrollment,
                enableDecryption,
                requireAuthentication,
                attestationChallenge,
                attestationMode
            )
        }

        val response = buildKeyResponse(
            generated.keyPair.public,
            keyFormat,
            authenticationType = authType,
            attestationCertificateChain = generated.attestationCertChain,
            attestationFailure = generated.attestationFailure
        )
        callback(Result.success(response))
    }

    private suspend fun createEcSigningKeys(
        activity: FlutterFragmentActivity,
        keyAlias: String?,
        callback: (Result<KeyCreationResult>) -> Unit,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        enforceBiometric: Boolean,
        keyFormat: KeyFormat,
        promptMessage: String,
        promptSubtitle: String?,
        promptDescription: String?,
        cancelButtonText: String,
        requireAuthentication: Boolean,
        attestationChallenge: ByteArray?,
        attestationMode: AttestationMode
    ) {
        var authType: AuthenticationType? = null
        if (enforceBiometric) {
            biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
            val outcome = biometricPromptHelper.authenticate(
                activity, promptMessage, promptSubtitle, promptDescription, cancelButtonText,
                useDeviceCredentials, null
            )
            authType = outcome.authenticationType
        }

        val generated = withContext(Dispatchers.IO) {
            keyManager.deleteKeysForAlias(keyAlias)
            keyManager.generateEcKeyInKeyStore(
                keyAlias,
                useDeviceCredentials,
                invalidateOnEnrollment,
                requireAuthentication,
                attestationChallenge,
                attestationMode
            )
        }

        val response = buildKeyResponse(
            generated.keyPair.public,
            keyFormat,
            authenticationType = authType,
            attestationCertificateChain = generated.attestationCertChain,
            attestationFailure = generated.attestationFailure
        )
        callback(Result.success(response))
    }

    private suspend fun createHybridEcKeys(
        activity: FlutterFragmentActivity,
        keyAlias: String?,
        callback: (Result<KeyCreationResult>) -> Unit,
        useDeviceCredentials: Boolean,
        invalidateOnEnrollment: Boolean,
        keyFormat: KeyFormat,
        enforceBiometric: Boolean,
        promptMessage: String,
        promptSubtitle: String?,
        promptDescription: String?,
        cancelButtonText: String,
        requireAuthentication: Boolean,
        attestationChallenge: ByteArray?,
        attestationMode: AttestationMode
    ) {
        if (enforceBiometric) {
            biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
            biometricPromptHelper.authenticate(
                activity, promptMessage, promptSubtitle, promptDescription, cancelButtonText,
                useDeviceCredentials, null
            )
        }

        // Key generation sits inside the try so a generateMasterKey failure, or a
        // cancellation withContext throws after its block created both keys, is
        // cleaned up too instead of leaving a signing-only EC key under the alias.
        // Cancellation can also stop the block before it runs, leaving the existing
        // key untouched, so the cancellation cleanup is skipped in that case.
        var keyGenerationStarted = false
        try {
            // Only the keystore EC signing key can carry an attestation chain;
            // the software decryption key generated below cannot be attested.
            val signingKey = withContext(Dispatchers.IO) {
                keyGenerationStarted = true
                keyManager.deleteKeysForAlias(keyAlias)
                val generated = keyManager.generateEcKeyInKeyStore(
                    keyAlias,
                    useDeviceCredentials,
                    invalidateOnEnrollment,
                    requireAuthentication,
                    attestationChallenge,
                    attestationMode
                )
                keyManager.generateMasterKey(keyAlias, useDeviceCredentials, invalidateOnEnrollment, requireAuthentication)
                generated
            }

            val cipherForWrap = withContext(Dispatchers.IO) { cryptoOperations.getCipherForEncryption(keyAlias) }

            val authenticatedCipher: Cipher
            val wrapAuthType: AuthenticationType
            if (requireAuthentication) {
                biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
                val wrapSuccess = biometricPromptHelper.authenticate(
                    activity, promptMessage, promptSubtitle, promptDescription, cancelButtonText,
                    useDeviceCredentials, BiometricPrompt.CryptoObject(cipherForWrap)
                )
                authenticatedCipher = wrapSuccess.cryptoObject?.cipher
                    ?: throw SecurityException("Authentication failed - no cipher returned")
                wrapAuthType = wrapSuccess.authenticationType
            } else {
                // No user authentication required: the master key is usable without
                // a BiometricPrompt, so seal the decryption key directly.
                authenticatedCipher = cipherForWrap
                wrapAuthType = AuthenticationType.UNKNOWN
            }

            val (wrappedBlob, publicKeyBytes) = withContext(Dispatchers.IO) {
                cryptoOperations.generateAndSealDecryptionEcKeyLocal(authenticatedCipher)
            }

            fileIOHelper.writeFileAtomic(Constants.ecWrappedFilename(keyAlias), wrappedBlob)
            fileIOHelper.writeFileAtomic(Constants.ecPubFilename(keyAlias), publicKeyBytes)

            val decryptingPublicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeyBytes))

            val response = buildKeyResponse(
                publicKey = signingKey.keyPair.public,
                format = keyFormat,
                decryptingKey = decryptingPublicKey,
                authenticationType = wrapAuthType,
                attestationCertificateChain = signingKey.attestationCertChain,
                attestationFailure = signingKey.attestationFailure
            )

            callback(Result.success(response))
        } catch (e: CancellationException) {
            if (keyGenerationStarted) {
                withContext(NonCancellable) { keyManager.deleteKeysForAlias(keyAlias) }
            }
            throw e
        } catch (e: Exception) {
            withContext(Dispatchers.IO) { keyManager.deleteKeysForAlias(keyAlias) }
            throw e
        }
    }

    override fun createSignature(
        payload: String,
        keyAlias: String?,
        config: CreateSignatureConfig?,
        signatureFormat: SignatureFormat,
        keyFormat: KeyFormat,
        promptMessage: String?,
        callback: (Result<SignatureResult>) -> Unit
    ) {
        if (payload.isBlank()) {
            callback(
                Result.success(
                    SignatureResult(
                        code = BiometricError.INVALID_INPUT,
                        error = "Payload is required"
                    )
                )
            )
            return
        }
        createSignatureInternal(
            payload.toByteArray(Charsets.UTF_8),
            keyAlias,
            config,
            signatureFormat,
            keyFormat,
            promptMessage,
            callback
        )
    }

    override fun createSignatureFromBytes(
        payload: ByteArray,
        keyAlias: String?,
        config: CreateSignatureConfig?,
        signatureFormat: SignatureFormat,
        keyFormat: KeyFormat,
        promptMessage: String?,
        callback: (Result<SignatureResult>) -> Unit
    ) {
        if (payload.isEmpty()) {
            callback(
                Result.success(
                    SignatureResult(
                        code = BiometricError.INVALID_INPUT,
                        error = "Payload is required"
                    )
                )
            )
            return
        }
        createSignatureInternal(payload, keyAlias, config, signatureFormat, keyFormat, promptMessage, callback)
    }

    private fun createSignatureInternal(
        payloadBytes: ByteArray,
        keyAlias: String?,
        config: CreateSignatureConfig?,
        signatureFormat: SignatureFormat,
        keyFormat: KeyFormat,
        promptMessage: String?,
        callback: (Result<SignatureResult>) -> Unit
    ) {
        val act = activity
        if (act == null) {
            callback(
                Result.success(
                    SignatureResult(
                        code = BiometricError.UNKNOWN,
                        error = "Foreground activity required"
                    )
                )
            )
            return
        }
        if (payloadBytes.isEmpty()) {
            callback(
                Result.success(
                    SignatureResult(
                        code = BiometricError.INVALID_INPUT,
                        error = "Payload is required"
                    )
                )
            )
            return
        }

        pluginScope.launch {
            try {
                val mode =
                    keyManager.inferKeyModeFromKeystore(keyAlias) ?: throw KeyNotFoundException("Signing key not found")
                val allowDeviceCredentials = config?.allowDeviceCredentials ?: false

                // Non-interactive key: the keystore key has no user-authentication
                // requirement, so sign directly without showing a BiometricPrompt.
                if (!keyManager.isUserAuthenticationRequired(keyAlias)) {
                    // Even without a prompt, the keystore operation opened at
                    // prepareSignature() can be pruned before sign() finishes:
                    // a backgrounded app's non-auth operation has the lowest
                    // pruning resistance, so keystore2 may evict it the moment
                    // any other operation needs a slot (INVALID_OPERATION_HANDLE
                    // / "outcome: Pruned"). The key is intact, so re-running
                    // begin() + finish() once recovers it.
                    var attempt = 0
                    var signatureBytes: ByteArray? = null
                    while (signatureBytes == null) {
                        try {
                            signatureBytes = withContext(Dispatchers.IO) {
                                val (signature, _) = cryptoOperations.prepareSignature(keyAlias, mode)
                                try {
                                    signature.update(payloadBytes)
                                    signature.sign()
                                } catch (e: IllegalArgumentException) {
                                    throw IllegalArgumentException("Invalid payload", e)
                                }
                            }
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            if (attempt < 1 && ErrorMapper.isPrunedOperationError(e)) {
                                attempt++
                                continue
                            }
                            throw e
                        }
                    }
                    val publicKey = cryptoOperations.getSigningPublicKey(keyAlias)
                    val response = buildSignatureResponse(
                        signatureBytes,
                        publicKey,
                        signatureFormat,
                        keyFormat,
                        AuthenticationType.UNKNOWN
                    )
                    callback(Result.success(response))
                    return@launch
                }

                // The Keystore signing operation is opened at prepareSignature() and
                // held open across the entire BiometricPrompt interaction. While a
                // device-credential (PIN/pattern) prompt is showing, this app is in the
                // background, so the operation has the lowest pruning resistance and
                // Android keystore2 can evict it (INVALID_OPERATION_HANDLE / "outcome:
                // Pruned") the moment any other operation needs a slot. The key itself
                // is intact, so re-running begin() + auth() + finish() once recovers it.
                var attempt = 0
                var signatureBytes: ByteArray? = null
                var resultAuthType: AuthenticationType = AuthenticationType.UNKNOWN
                while (signatureBytes == null) {
                    try {
                        val (_, cryptoObject) = withContext(Dispatchers.IO) {
                            cryptoOperations.prepareSignature(keyAlias, mode)
                        }

                        biometricPromptHelper.checkBiometricAvailability(act, allowDeviceCredentials)

                        val successOutcome = biometricPromptHelper.authenticate(
                            act, promptMessage ?: "Authenticate", config?.promptSubtitle, config?.promptDescription,
                            config?.cancelButtonText ?: "Cancel", allowDeviceCredentials, cryptoObject
                        )

                        val authenticatedCrypto = successOutcome.cryptoObject
                        signatureBytes = withContext(Dispatchers.IO) {
                            val sig = authenticatedCrypto?.signature
                                ?: throw SecurityException("Biometric authentication did not return an authenticated signature")
                            try {
                                sig.update(payloadBytes)
                                sig.sign()
                            } catch (e: IllegalArgumentException) {
                                throw IllegalArgumentException("Invalid payload", e)
                            }
                        }
                        resultAuthType = successOutcome.authenticationType
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        if (attempt < 1 && ErrorMapper.isPrunedOperationError(e)) {
                            attempt++
                            continue
                        }
                        throw e
                    }
                }

                val publicKey = cryptoOperations.getSigningPublicKey(keyAlias)
                val response =
                    buildSignatureResponse(signatureBytes, publicKey, signatureFormat, keyFormat, resultAuthType)
                callback(Result.success(response))

            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                callback(
                    Result.success(
                        SignatureResult(
                            code = ErrorMapper.mapToBiometricError(e),
                            error = ErrorMapper.safeErrorMessage(e)
                        )
                    )
                )
            }
        }
    }

    override fun decrypt(
        payload: String,
        keyAlias: String?,
        payloadFormat: PayloadFormat,
        config: DecryptConfig?,
        promptMessage: String?,
        callback: (Result<DecryptResult>) -> Unit
    ) {
        if (payload.isBlank()) {
            callback(Result.success(DecryptResult(code = BiometricError.INVALID_INPUT, error = "Payload is required")))
            return
        }
        // Decode it up front too, so malformed input is reported before any key
        // access or prompt.
        val encryptedBytes = try {
            FormatUtils.parsePayload(payload, payloadFormat)
        } catch (e: IllegalArgumentException) {
            null
        }
        if (encryptedBytes == null || encryptedBytes.isEmpty()) {
            callback(Result.success(DecryptResult(code = BiometricError.INVALID_INPUT, error = "Invalid payload")))
            return
        }
        val act = activity
        if (act == null) {
            callback(
                Result.success(
                    DecryptResult(
                        code = BiometricError.UNKNOWN,
                        error = "Foreground activity required"
                    )
                )
            )
            return
        }

        pluginScope.launch {
            try {
                val mode = keyManager.inferKeyModeFromKeystore(keyAlias) ?: throw KeyNotFoundException("Keys not found")

                if (mode == KeyMode.EC_SIGN_ONLY) {
                    throw SecurityException("Decryption not enabled for EC signing-only mode")
                }

                // Non-interactive key: decrypt directly without a BiometricPrompt.
                if (!keyManager.isUserAuthenticationRequired(keyAlias)) {
                    val data = withContext(Dispatchers.IO) {
                        when (mode) {
                            KeyMode.RSA -> {
                                val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
                                val alias = Constants.biometricKeyAlias(keyAlias)
                                val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                                    ?: throw KeyNotFoundException("RSA key not found")
                                val cipher = try {
                                    Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").apply {
                                        init(Cipher.DECRYPT_MODE, entry.privateKey)
                                    }
                                } catch (e: InvalidKeyException) {
                                    Cipher.getInstance("RSA/ECB/PKCS1Padding").apply {
                                        init(Cipher.DECRYPT_MODE, entry.privateKey)
                                    }
                                }
                                String(cipher.doFinal(encryptedBytes), Charsets.UTF_8)
                            }

                            KeyMode.HYBRID_EC -> {
                                val cipher = cryptoOperations.getCipherForDecryption(keyAlias)
                                    ?: throw KeyNotFoundException("Decryption keys not found")
                                cryptoOperations.performEciesDecryption(keyAlias, cipher, encryptedBytes)
                            }

                            else -> throw SecurityException("Unsupported decryption mode")
                        }
                    }
                    callback(
                        Result.success(
                            DecryptResult(
                                decryptedData = data,
                                code = BiometricError.SUCCESS,
                                authenticationType = AuthenticationType.UNKNOWN
                            )
                        )
                    )
                    return@launch
                }

                val allowDeviceCredentials = config?.allowDeviceCredentials ?: false
                val prompt = promptMessage ?: "Authenticate"
                val subtitle = config?.promptSubtitle
                val description = config?.promptDescription
                val cancel = config?.cancelButtonText ?: "Cancel"

                val success = when (mode) {
                    KeyMode.RSA -> decryptRsa(
                        act,
                        keyAlias,
                        encryptedBytes,
                        prompt,
                        subtitle,
                        description,
                        cancel,
                        allowDeviceCredentials
                    )

                    KeyMode.HYBRID_EC -> decryptHybridEc(
                        act,
                        keyAlias,
                        encryptedBytes,
                        prompt,
                        subtitle,
                        description,
                        cancel,
                        allowDeviceCredentials
                    )

                    else -> throw SecurityException("Unsupported decryption mode")
                }

                callback(
                    Result.success(
                        DecryptResult(
                            decryptedData = success.data,
                            code = BiometricError.SUCCESS,
                            authenticationType = success.authenticationType
                        )
                    )
                )

            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                callback(
                    Result.success(
                        DecryptResult(
                            code = ErrorMapper.mapToBiometricError(e),
                            error = ErrorMapper.safeErrorMessage(e)
                        )
                    )
                )
            }
        }
    }

    private data class DecryptSuccess(val data: String, val authenticationType: AuthenticationType)

    private suspend fun decryptRsa(
        activity: FlutterFragmentActivity,
        keyAlias: String?,
        encryptedBytes: ByteArray,
        prompt: String,
        subtitle: String?,
        description: String?,
        cancel: String,
        allowDeviceCredentials: Boolean
    ): DecryptSuccess {
        val cipher = withContext(Dispatchers.IO) {
            val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
            val alias = Constants.biometricKeyAlias(keyAlias)
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                ?: throw KeyNotFoundException("RSA key not found")
            openRsaDecryptCipher(entry.privateKey)
        }

        biometricPromptHelper.checkBiometricAvailability(activity, allowDeviceCredentials)

        val successOutcome = biometricPromptHelper.authenticate(
            activity, prompt, subtitle, description, cancel, allowDeviceCredentials,
            BiometricPrompt.CryptoObject(cipher)
        )

        val decrypted = withContext(Dispatchers.IO) {
            val authenticatedCipher = successOutcome.cryptoObject?.cipher
                ?: throw SecurityException("Authentication failed - no cipher returned")
            authenticatedCipher.doFinal(encryptedBytes)
        }

        return DecryptSuccess(String(decrypted, Charsets.UTF_8), successOutcome.authenticationType)
    }

    /**
     * Opens the cipher used to decrypt an RSA payload, preferring OAEP with both digests pinned.
     *
     * `Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")` names only the main digest;
     * AndroidKeyStore then picks the MGF1 digest itself and has always chosen SHA-1. Relying on
     * that undocumented default means a future platform change could make already-encrypted data
     * undecryptable, so the primary path states both digests explicitly via
     * [Constants.RSA_OAEP_SHA256_MGF1_SHA1]. SHA-1 reproduces the parameters every existing
     * ciphertext was built with, so pinning is behaviour-preserving.
     *
     * Two fallbacks stay in place so no key that decrypts today stops decrypting:
     * a provider that rejects the explicit spec still gets the previous unparameterised OAEP
     * call, and keys created before v11.0.0 — which only authorise PKCS#1 v1.5 — still reach
     * that transformation.
     */
    private fun openRsaDecryptCipher(privateKey: PrivateKey): Cipher =
        try {
            Cipher.getInstance(Constants.RSA_OAEP_TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, privateKey, Constants.RSA_OAEP_SHA256_MGF1_SHA1)
            }
        } catch (_: GeneralSecurityException) {
            try {
                Cipher.getInstance(Constants.RSA_OAEP_SHA256_TRANSFORMATION).apply {
                    init(Cipher.DECRYPT_MODE, privateKey)
                }
            } catch (_: GeneralSecurityException) {
                Cipher.getInstance(Constants.RSA_PKCS1_TRANSFORMATION).apply {
                    init(Cipher.DECRYPT_MODE, privateKey)
                }
            }
        }

    private suspend fun decryptHybridEc(
        activity: FlutterFragmentActivity,
        keyAlias: String?,
        encryptedBytes: ByteArray,
        prompt: String,
        subtitle: String?,
        description: String?,
        cancel: String,
        allowDeviceCredentials: Boolean
    ): DecryptSuccess {
        val cipher = withContext(Dispatchers.IO) { cryptoOperations.getCipherForDecryption(keyAlias) }
            ?: throw KeyNotFoundException("Decryption keys not found")
        // Reject input that can't be an ECIES payload before prompting for it.
        cryptoOperations.requireEciesPayload(encryptedBytes)

        biometricPromptHelper.checkBiometricAvailability(activity, allowDeviceCredentials)

        val successOutcome = biometricPromptHelper.authenticate(
            activity, prompt, subtitle, description, cancel, allowDeviceCredentials,
            BiometricPrompt.CryptoObject(cipher)
        )

        val data = withContext(Dispatchers.IO) {
            val authenticatedCipher = successOutcome.cryptoObject?.cipher
                ?: throw SecurityException("Authentication failed - no cipher returned")
            cryptoOperations.performEciesDecryption(keyAlias, authenticatedCipher, encryptedBytes)
        }

        return DecryptSuccess(data, successOutcome.authenticationType)
    }

    override fun deleteKeys(keyAlias: String?, callback: (Result<Boolean>) -> Unit) {
        pluginScope.launch {
            withContext(Dispatchers.IO) { keyManager.deleteKeysForAlias(keyAlias) }
            callback(Result.success(true))
        }
    }

    override fun deleteAllKeys(callback: (Result<Boolean>) -> Unit) {
        pluginScope.launch {
            withContext(Dispatchers.IO) { keyManager.deleteAllKeys() }
            callback(Result.success(true))
        }
    }

    override fun getKeyInfo(
        keyAlias: String?,
        checkValidity: Boolean,
        keyFormat: KeyFormat,
        callback: (Result<KeyInfo>) -> Unit
    ) {
        pluginScope.launch {
            try {
                val keyInfo = withContext(Dispatchers.IO) {
                    val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
                    val alias = Constants.biometricKeyAlias(keyAlias)
                    if (!keyStore.containsAlias(alias)) {
                        return@withContext KeyInfo(exists = false)
                    }

                    val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                        ?: return@withContext KeyInfo(exists = false)

                    val publicKey = entry.certificate.publicKey
                    val mode = keyManager.inferKeyModeFromKeystore(keyAlias)

                    val isValid = if (checkValidity) {
                        probeKeyValidityAndRelease(entry.privateKey, mode)
                    } else {
                        null
                    }

                    val algorithm = publicKey.algorithm
                    val keySize = (publicKey as? java.security.interfaces.RSAKey)?.modulus?.bitLength()?.toLong()
                        ?: (publicKey as? java.security.interfaces.ECKey)?.params?.order?.bitLength()?.toLong()

                    val formattedPublicKey = FormatUtils.formatOutput(publicKey.encoded, keyFormat)

                    val isHybridMode = mode == KeyMode.HYBRID_EC
                    val decryptingInfo = if (isHybridMode) {
                        val pubBytes = fileIOHelper.readFileIfExists(Constants.ecPubFilename(keyAlias))
                        if (pubBytes != null) {
                            val decryptKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(pubBytes))
                            Triple(FormatUtils.formatOutput(decryptKey.encoded, keyFormat).value, "EC", 256L)
                        } else null
                    } else null

                    // Null for unattested keys (a single self-signed keystore
                    // certificate). attestationChainOf never throws, so a chain
                    // encoding failure can't collapse the whole result into the
                    // catch below (exists = false).
                    val attestationChain = keyManager.attestationChainOf(entry.certificateChain)

                    KeyInfo(
                        exists = true,
                        isValid = isValid,
                        algorithm = algorithm,
                        keySize = keySize,
                        isHybridMode = isHybridMode,
                        publicKey = formattedPublicKey.value,
                        decryptingPublicKey = decryptingInfo?.first,
                        decryptingAlgorithm = decryptingInfo?.second,
                        decryptingKeySize = decryptingInfo?.third,
                        attestationCertificateChain = attestationChain
                    )
                }
                callback(Result.success(keyInfo))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                callback(Result.success(KeyInfo(exists = false)))
            }
        }
    }

    /**
     * Probes whether [privateKey] is still usable (i.e. not invalidated by new
     * biometric enrollment) and releases the KeyMint operation immediately.
     *
     * Signature.initSign begins a KeyMint operation. On StrongBox the slot pool
     * is tiny, and a probe operation left dangling until GC accumulates and
     * triggers TOO_MANY_OPERATIONS, which makes keystore2 prune in-flight
     * signing operations (surfacing as INVALID_OPERATION_HANDLE / pruned). We
     * therefore drive the probe to a terminal state right away so its slot is
     * freed now instead of at an indeterminate GC point.
     */
    private fun probeKeyValidityAndRelease(privateKey: PrivateKey, mode: KeyMode?): Boolean {
        val algorithm = when (mode) {
            KeyMode.RSA -> "SHA256withRSA"
            else -> "SHA256withECDSA"
        }
        val signature = Signature.getInstance(algorithm)
        try {
            signature.initSign(privateKey)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // The key was invalidated (e.g. by new biometric enrollment).
            return false
        } catch (e: Exception) {
            // Could not even begin the operation: treat as not usable, matching
            // the previous behaviour.
            return false
        }

        // initSign opened a KeyMint operation. Drive it to a terminal state so
        // the slot is released now rather than lingering until GC.
        try {
            signature.update(byteArrayOf(0))
            signature.sign()
        } catch (_: Exception) {
            // A user-authentication-bound key cannot be exercised without a
            // fresh prompt, so finish() fails here, but that failure still
            // finalizes (and frees) the operation. The key itself is valid: it
            // was not KeyPermanentlyInvalidated above.
        }
        return true
    }

    override fun simplePrompt(
        promptMessage: String,
        config: SimplePromptConfig?,
        callback: (Result<SimplePromptResult>) -> Unit
    ) {
        val act = activity
        if (act == null) {
            callback(
                Result.success(
                    SimplePromptResult(
                        success = false,
                        error = "Foreground activity required",
                        code = BiometricError.PROMPT_ERROR
                    )
                )
            )
            return
        }

        pluginScope.launch {
            try {
                val allowDeviceCredentials = config?.allowDeviceCredentials ?: false
                val biometricStrength = config?.biometricStrength ?: BiometricStrength.STRONG

                val authenticators = biometricPromptHelper.getAuthenticators(allowDeviceCredentials, biometricStrength)
                val canAuth = androidx.biometric.BiometricManager.from(act).canAuthenticate(authenticators)

                if (canAuth != androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS) {
                    val (errorCode, errorMsg) = ErrorMapper.mapBiometricManagerError(canAuth, biometricStrength)
                    callback(Result.success(SimplePromptResult(success = false, error = errorMsg, code = errorCode)))
                    return@launch
                }

                val cancelText = config?.cancelButtonText ?: "Cancel"

                val successOutcome = biometricPromptHelper.authenticate(
                    act, promptMessage, config?.subtitle, config?.description,
                    cancelText, allowDeviceCredentials, null
                )

                callback(
                    Result.success(
                        SimplePromptResult(
                            success = true,
                            code = BiometricError.SUCCESS,
                            authenticationType = successOutcome.authenticationType
                        )
                    )
                )

            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val errorCode = ErrorMapper.mapToBiometricError(e)
                callback(
                    Result.success(
                        SimplePromptResult(
                            success = false,
                            error = ErrorMapper.safeErrorMessage(e),
                            code = errorCode
                        )
                    )
                )
            }
        }
    }

    override fun isDeviceLockSet(callback: (Result<Boolean>) -> Unit) {
        val keyguardManager =
            appContext.getSystemService(android.content.Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
        callback(Result.success(keyguardManager.isDeviceSecure))
    }

    private fun buildKeyResponse(
        publicKey: PublicKey,
        format: KeyFormat,
        decryptingKey: PublicKey? = null,
        authenticationType: AuthenticationType? = null,
        attestationCertificateChain: List<ByteArray>? = null,
        attestationFailure: KeyAttestationException? = null
    ): KeyCreationResult {
        val formatted = FormatUtils.formatOutput(publicKey.encoded, format)
        val keySize = (publicKey as? java.security.interfaces.RSAKey)?.modulus?.bitLength()
            ?: (publicKey as? java.security.interfaces.ECKey)?.params?.order?.bitLength()

        var decryptingFormatted: FormatUtils.FormattedOutput? = null
        var decryptingAlgorithm: String? = null
        var decryptingKeySize: Long? = null

        if (decryptingKey != null) {
            decryptingFormatted = FormatUtils.formatOutput(decryptingKey.encoded, format)
            decryptingAlgorithm = decryptingKey.algorithm
            decryptingKeySize = ((decryptingKey as? java.security.interfaces.RSAKey)?.modulus?.bitLength()
                ?: (decryptingKey as? java.security.interfaces.ECKey)?.params?.order?.bitLength())?.toLong()
        }

        return KeyCreationResult(
            publicKey = formatted.value,
            publicKeyBytes = publicKey.encoded,
            code = BiometricError.SUCCESS,
            algorithm = publicKey.algorithm,
            keySize = keySize?.toLong(),
            decryptingPublicKey = decryptingFormatted?.value,
            decryptingAlgorithm = decryptingAlgorithm,
            decryptingKeySize = decryptingKeySize,
            isHybridMode = decryptingKey != null,
            authenticationType = authenticationType,
            attestationCertificateChain = attestationCertificateChain,
            attestationErrorCode = attestationFailure?.errorCode,
            attestationError = attestationFailure?.message
        )
    }

    private fun buildSignatureResponse(
        signatureBytes: ByteArray,
        publicKey: PublicKey,
        format: SignatureFormat,
        keyFormat: KeyFormat,
        authenticationType: AuthenticationType
    ): SignatureResult {
        val sigString = when (format) {
            SignatureFormat.BASE64, SignatureFormat.RAW -> android.util.Base64.encodeToString(
                signatureBytes,
                android.util.Base64.NO_WRAP
            )

            SignatureFormat.HEX -> FormatUtils.bytesToHex(signatureBytes)
        }

        val pubFormatted = FormatUtils.formatOutput(publicKey.encoded, keyFormat)
        val keySize = (publicKey as? java.security.interfaces.RSAKey)?.modulus?.bitLength()
            ?: (publicKey as? java.security.interfaces.ECKey)?.params?.order?.bitLength()

        return SignatureResult(
            signature = sigString,
            signatureBytes = signatureBytes,
            publicKey = pubFormatted.value,
            code = BiometricError.SUCCESS,
            algorithm = publicKey.algorithm,
            keySize = keySize?.toLong(),
            authenticationType = authenticationType
        )
    }
}
