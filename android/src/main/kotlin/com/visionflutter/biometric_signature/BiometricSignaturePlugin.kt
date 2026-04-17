package com.visionflutter.biometric_signature

import android.content.Context
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
        activity?.let { biometricPromptHelper.registerAuthLauncher(it) }
    }

    override fun onDetachedFromActivity() {
        biometricPromptHelper.clearAuthLauncher()
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

                val useDeviceCredentials = config?.useDeviceCredentials ?: false
                val enableDecryption = config?.enableDecryption ?: false
                val invalidateOnEnrollment = config?.setInvalidatedByBiometricEnrollment ?: true
                val signatureType = config?.signatureType ?: SignatureType.RSA
                val enforceBiometric = config?.enforceBiometric ?: false

                val mode = when (signatureType) {
                    SignatureType.RSA -> KeyMode.RSA
                    SignatureType.ECDSA -> if (enableDecryption) KeyMode.HYBRID_EC else KeyMode.EC_SIGN_ONLY
                }

                val prompt = promptMessage ?: "Authenticate to create keys"
                val fallbackOptions = config?.fallbackOptions

                when (mode) {
                    KeyMode.RSA -> createRsaKeys(act, keyAlias, callback, useDeviceCredentials, invalidateOnEnrollment, enableDecryption, enforceBiometric, keyFormat, prompt, fallbackOptions)
                    KeyMode.EC_SIGN_ONLY -> createEcSigningKeys(act, keyAlias, callback, useDeviceCredentials, invalidateOnEnrollment, enforceBiometric, keyFormat, prompt, fallbackOptions)
                    KeyMode.HYBRID_EC -> createHybridEcKeys(act, keyAlias, callback, useDeviceCredentials, invalidateOnEnrollment, keyFormat, enforceBiometric, prompt, fallbackOptions)
                }
            } catch (e: CancellationException) {
                throw e
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
        fallbackOptions: List<BiometricFallbackOption?>? = null
    ) {
        var authType: AuthenticationType? = null
        if (enforceBiometric) {
            biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
            val outcome = authenticateWithOptionalFallback(
                activity, promptMessage, null, null, "Cancel",
                useDeviceCredentials, null, fallbackOptions
            )
            if (outcome is AuthenticationOutcome.FallbackSelected) {
                callback(Result.success(KeyCreationResult(
                    code = BiometricError.FALLBACK_SELECTED,
                    error = "Fallback option selected"
                )))
                return
            }
            authType = (outcome as AuthenticationOutcome.Success).authenticationType
        }

        val keyPair = withContext(Dispatchers.IO) {
            keyManager.deleteKeysForAlias(keyAlias)
            keyManager.generateRsaKeyInKeyStore(keyAlias, useDeviceCredentials, invalidateOnEnrollment, enableDecryption)
        }

        val response = buildKeyResponse(keyPair.public, keyFormat, authenticationType = authType)
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
        fallbackOptions: List<BiometricFallbackOption?>? = null
    ) {
        var authType: AuthenticationType? = null
        if (enforceBiometric) {
            biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
            val outcome = authenticateWithOptionalFallback(
                activity, promptMessage, null, null, "Cancel",
                useDeviceCredentials, null, fallbackOptions
            )
            if (outcome is AuthenticationOutcome.FallbackSelected) {
                callback(Result.success(KeyCreationResult(
                    code = BiometricError.FALLBACK_SELECTED,
                    error = "Fallback option selected"
                )))
                return
            }
            authType = (outcome as AuthenticationOutcome.Success).authenticationType
        }

        val keyPair = withContext(Dispatchers.IO) {
            keyManager.deleteKeysForAlias(keyAlias)
            keyManager.generateEcKeyInKeyStore(keyAlias, useDeviceCredentials, invalidateOnEnrollment)
        }

        val response = buildKeyResponse(keyPair.public, keyFormat, authenticationType = authType)
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
        fallbackOptions: List<BiometricFallbackOption?>? = null
    ) {
        if (enforceBiometric) {
            biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
            val outcome = authenticateWithOptionalFallback(
                activity, promptMessage, null, null, "Cancel",
                useDeviceCredentials, null, fallbackOptions
            )
            if (outcome is AuthenticationOutcome.FallbackSelected) {
                callback(Result.success(KeyCreationResult(
                    code = BiometricError.FALLBACK_SELECTED,
                    error = "Fallback option selected"
                )))
                return
            }
        }

        val signingKeyPair = withContext(Dispatchers.IO) {
            keyManager.deleteKeysForAlias(keyAlias)
            val ecKeyPair = keyManager.generateEcKeyInKeyStore(keyAlias, useDeviceCredentials, invalidateOnEnrollment)
            keyManager.generateMasterKey(keyAlias, useDeviceCredentials, invalidateOnEnrollment)
            ecKeyPair
        }

        try {
            val cipherForWrap = withContext(Dispatchers.IO) { cryptoOperations.getCipherForEncryption(keyAlias) }

            biometricPromptHelper.checkBiometricAvailability(activity, useDeviceCredentials)
            val wrapOutcome = authenticateWithOptionalFallback(
                activity, promptMessage, null, null, "Cancel",
                useDeviceCredentials, BiometricPrompt.CryptoObject(cipherForWrap), fallbackOptions
            )
            if (wrapOutcome is AuthenticationOutcome.FallbackSelected) {
                withContext(Dispatchers.IO) { keyManager.deleteKeysForAlias(keyAlias) }
                callback(Result.success(KeyCreationResult(
                    code = BiometricError.FALLBACK_SELECTED,
                    error = "Fallback option selected"
                )))
                return
            }

            val wrapSuccess = wrapOutcome as AuthenticationOutcome.Success
            val authenticatedCipher = wrapSuccess.cryptoObject?.cipher
                ?: throw SecurityException("Authentication failed - no cipher returned")

            val (wrappedBlob, publicKeyBytes) = withContext(Dispatchers.IO) {
                cryptoOperations.generateAndSealDecryptionEcKeyLocal(authenticatedCipher)
            }

            fileIOHelper.writeFileAtomic(Constants.ecWrappedFilename(keyAlias), wrappedBlob)
            fileIOHelper.writeFileAtomic(Constants.ecPubFilename(keyAlias), publicKeyBytes)

            val decryptingPublicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeyBytes))

            val response = buildKeyResponse(
                publicKey = signingKeyPair.public,
                format = keyFormat,
                decryptingKey = decryptingPublicKey,
                authenticationType = wrapSuccess.authenticationType
            )

            callback(Result.success(response))
        } catch (e: CancellationException) {
            withContext(NonCancellable) { keyManager.deleteKeysForAlias(keyAlias) }
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
        val act = activity
        if (act == null) {
            callback(Result.success(SignatureResult(code = BiometricError.UNKNOWN, error = "Foreground activity required")))
            return
        }
        if (payload.isBlank()) {
            callback(Result.success(SignatureResult(code = BiometricError.INVALID_INPUT, error = "Payload is required")))
            return
        }

        pluginScope.launch {
            try {
                val mode = keyManager.inferKeyModeFromKeystore(keyAlias) ?: throw SecurityException("Signing key not found")
                val allowDeviceCredentials = config?.allowDeviceCredentials ?: false
                val fallbackOptions = config?.fallbackOptions

                val (signature, cryptoObject) = withContext(Dispatchers.IO) {
                    cryptoOperations.prepareSignature(keyAlias, mode)
                }

                biometricPromptHelper.checkBiometricAvailability(act, allowDeviceCredentials)

                val outcome = authenticateWithOptionalFallback(
                    act, promptMessage ?: "Authenticate", config?.promptSubtitle, null,
                    config?.cancelButtonText ?: "Cancel", allowDeviceCredentials, cryptoObject,
                    fallbackOptions
                )

                if (outcome is AuthenticationOutcome.FallbackSelected) {
                    callback(Result.success(SignatureResult(
                        code = BiometricError.FALLBACK_SELECTED,
                        error = "Fallback option selected",
                        selectedFallbackIndex = outcome.index,
                        selectedFallbackText = outcome.text
                    )))
                    return@launch
                }

                val successOutcome = outcome as AuthenticationOutcome.Success
                val authenticatedCrypto = successOutcome.cryptoObject

                val signatureBytes = withContext(Dispatchers.IO) {
                    val sig = authenticatedCrypto?.signature ?: throw SecurityException("Biometric authentication did not return an authenticated signature")
                    try {
                        sig.update(payload.toByteArray(Charsets.UTF_8))
                        sig.sign()
                    } catch (e: IllegalArgumentException) {
                        throw IllegalArgumentException("Invalid payload", e)
                    }
                }

                val publicKey = cryptoOperations.getSigningPublicKey(keyAlias)
                val response = buildSignatureResponse(signatureBytes, publicKey, signatureFormat, keyFormat, successOutcome.authenticationType)
                callback(Result.success(response))

            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                callback(Result.success(SignatureResult(code = ErrorMapper.mapToBiometricError(e), error = ErrorMapper.safeErrorMessage(e))))
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
        val act = activity
        if (act == null) {
            callback(Result.success(DecryptResult(code = BiometricError.UNKNOWN, error = "Foreground activity required")))
            return
        }
        if (payload.isBlank()) {
            callback(Result.success(DecryptResult(code = BiometricError.INVALID_INPUT, error = "Payload is required")))
            return
        }

        pluginScope.launch {
            try {
                val mode = keyManager.inferKeyModeFromKeystore(keyAlias) ?: throw SecurityException("Keys not found")

                if (mode == KeyMode.EC_SIGN_ONLY) {
                    throw SecurityException("Decryption not enabled for EC signing-only mode")
                }

                val allowDeviceCredentials = config?.allowDeviceCredentials ?: false
                val prompt = promptMessage ?: "Authenticate"
                val subtitle = config?.promptSubtitle
                val cancel = config?.cancelButtonText ?: "Cancel"
                val fallbackOptions = config?.fallbackOptions

                val decryptResult = when (mode) {
                    KeyMode.RSA -> decryptRsa(act, keyAlias, payload, payloadFormat, prompt, subtitle, cancel, allowDeviceCredentials, fallbackOptions)
                    KeyMode.HYBRID_EC -> decryptHybridEc(act, keyAlias, payload, payloadFormat, prompt, subtitle, cancel, allowDeviceCredentials, fallbackOptions)
                    else -> throw SecurityException("Unsupported decryption mode")
                }

                if (decryptResult is DecryptOutcome.FallbackSelected) {
                    callback(Result.success(DecryptResult(
                        code = BiometricError.FALLBACK_SELECTED,
                        error = "Fallback option selected",
                        selectedFallbackIndex = decryptResult.index,
                        selectedFallbackText = decryptResult.text
                    )))
                } else {
                    val success = decryptResult as DecryptOutcome.Success
                    callback(Result.success(DecryptResult(
                        decryptedData = success.data,
                        code = BiometricError.SUCCESS,
                        authenticationType = success.authenticationType
                    )))
                }

            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                callback(Result.success(DecryptResult(code = ErrorMapper.mapToBiometricError(e), error = ErrorMapper.safeErrorMessage(e))))
            }
        }
    }

    private sealed interface DecryptOutcome {
        data class Success(val data: String, val authenticationType: AuthenticationType) : DecryptOutcome
        data class FallbackSelected(val index: Long?, val text: String) : DecryptOutcome
    }

    private suspend fun decryptRsa(
        activity: FlutterFragmentActivity,
        keyAlias: String?,
        payload: String,
        payloadFormat: PayloadFormat,
        prompt: String,
        subtitle: String?,
        cancel: String,
        allowDeviceCredentials: Boolean,
        fallbackOptions: List<BiometricFallbackOption?>? = null
    ): DecryptOutcome {
        val cipher = withContext(Dispatchers.IO) {
            val keyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER).apply { load(null) }
            val alias = Constants.biometricKeyAlias(keyAlias)
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                ?: throw IllegalStateException("RSA key not found")
            try {
                Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").apply {
                    init(Cipher.DECRYPT_MODE, entry.privateKey)
                }
            } catch (e: InvalidKeyException) {
                Cipher.getInstance("RSA/ECB/PKCS1Padding").apply {
                    init(Cipher.DECRYPT_MODE, entry.privateKey)
                }
            }
        }

        biometricPromptHelper.checkBiometricAvailability(activity, allowDeviceCredentials)

        val outcome = authenticateWithOptionalFallback(
            activity, prompt, subtitle, null, cancel, allowDeviceCredentials,
            BiometricPrompt.CryptoObject(cipher), fallbackOptions
        )

        if (outcome is AuthenticationOutcome.FallbackSelected) {
            return DecryptOutcome.FallbackSelected(outcome.index, outcome.text)
        }

        val successOutcome = outcome as AuthenticationOutcome.Success
        val decrypted = withContext(Dispatchers.IO) {
            val authenticatedCipher = successOutcome.cryptoObject?.cipher
                ?: throw SecurityException("Authentication failed - no cipher returned")
            try {
                val encryptedBytes = FormatUtils.parsePayload(payload, payloadFormat)
                authenticatedCipher.doFinal(encryptedBytes)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("Invalid Base64 payload", e)
            }
        }

        return DecryptOutcome.Success(String(decrypted, Charsets.UTF_8), successOutcome.authenticationType)
    }

    private suspend fun decryptHybridEc(
        activity: FlutterFragmentActivity,
        keyAlias: String?,
        payload: String,
        payloadFormat: PayloadFormat,
        prompt: String,
        subtitle: String?,
        cancel: String,
        allowDeviceCredentials: Boolean,
        fallbackOptions: List<BiometricFallbackOption?>? = null
    ): DecryptOutcome {
        val cipher = withContext(Dispatchers.IO) { cryptoOperations.getCipherForDecryption(keyAlias) }
            ?: throw SecurityException("Decryption keys not found")

        biometricPromptHelper.checkBiometricAvailability(activity, allowDeviceCredentials)

        val outcome = authenticateWithOptionalFallback(
            activity, prompt, subtitle, null, cancel, allowDeviceCredentials,
            BiometricPrompt.CryptoObject(cipher), fallbackOptions
        )

        if (outcome is AuthenticationOutcome.FallbackSelected) {
            return DecryptOutcome.FallbackSelected(outcome.index, outcome.text)
        }

        val successOutcome = outcome as AuthenticationOutcome.Success
        val data = withContext(Dispatchers.IO) {
            val authenticatedCipher = successOutcome.cryptoObject?.cipher
                ?: throw SecurityException("Authentication failed - no cipher returned")
            cryptoOperations.performEciesDecryption(keyAlias, authenticatedCipher, payload, payloadFormat)
        }

        return DecryptOutcome.Success(data, successOutcome.authenticationType)
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
                        runCatching {
                            val algorithm = when (mode) {
                                KeyMode.RSA -> "SHA256withRSA"
                                else -> "SHA256withECDSA"
                            }
                            val signature = java.security.Signature.getInstance(algorithm)
                            signature.initSign(entry.privateKey)
                            true
                        }.getOrDefault(false)
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

                    KeyInfo(
                        exists = true,
                        isValid = isValid,
                        algorithm = algorithm,
                        keySize = keySize,
                        isHybridMode = isHybridMode,
                        publicKey = formattedPublicKey.value,
                        decryptingPublicKey = decryptingInfo?.first,
                        decryptingAlgorithm = decryptingInfo?.second,
                        decryptingKeySize = decryptingInfo?.third
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

    override fun simplePrompt(
        promptMessage: String,
        config: SimplePromptConfig?,
        callback: (Result<SimplePromptResult>) -> Unit
    ) {
        val act = activity
        if (act == null) {
            callback(Result.success(SimplePromptResult(success = false, error = "Foreground activity required", code = BiometricError.PROMPT_ERROR)))
            return
        }

        pluginScope.launch {
            try {
                val allowDeviceCredentials = config?.allowDeviceCredentials ?: false
                val biometricStrength = config?.biometricStrength ?: BiometricStrength.STRONG
                val fallbackOptions = config?.fallbackOptions

                val authenticators = biometricPromptHelper.getAuthenticators(allowDeviceCredentials, biometricStrength)
                val canAuth = androidx.biometric.BiometricManager.from(act).canAuthenticate(authenticators)

                if (canAuth != androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS) {
                    val (errorCode, errorMsg) = ErrorMapper.mapBiometricManagerError(canAuth, biometricStrength)
                    callback(Result.success(SimplePromptResult(success = false, error = errorMsg, code = errorCode)))
                    return@launch
                }

                val cancelText = config?.cancelButtonText ?: "Cancel"

                val outcome = authenticateWithOptionalFallback(
                    act, promptMessage, config?.subtitle, config?.description,
                    cancelText, allowDeviceCredentials, null, fallbackOptions
                )

                if (outcome is AuthenticationOutcome.FallbackSelected) {
                    callback(Result.success(SimplePromptResult(
                        success = false,
                        code = BiometricError.FALLBACK_SELECTED,
                        error = "Fallback option selected",
                        selectedFallbackIndex = outcome.index,
                        selectedFallbackText = outcome.text
                    )))
                } else {
                    val successOutcome = outcome as AuthenticationOutcome.Success
                    callback(Result.success(SimplePromptResult(
                        success = true,
                        code = BiometricError.SUCCESS,
                        authenticationType = successOutcome.authenticationType
                    )))
                }

            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val errorCode = ErrorMapper.mapToBiometricError(e)
                callback(Result.success(SimplePromptResult(success = false, error = ErrorMapper.safeErrorMessage(e), code = errorCode)))
            }
        }
    }

    override fun isDeviceLockSet(callback: (Result<Boolean>) -> Unit) {
        val keyguardManager = appContext.getSystemService(android.content.Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
        callback(Result.success(keyguardManager.isDeviceSecure))
    }

    private fun hasFallbackOptions(options: List<BiometricFallbackOption?>?): Boolean {
        return options != null && options.any { it?.text != null }
    }

    private suspend fun authenticateWithOptionalFallback(
        activity: FlutterFragmentActivity,
        title: String,
        subtitle: String?,
        description: String?,
        cancelText: String,
        allowDeviceCredentials: Boolean,
        cryptoObject: BiometricPrompt.CryptoObject?,
        fallbackOptions: List<BiometricFallbackOption?>?
    ): AuthenticationOutcome {
        return if (hasFallbackOptions(fallbackOptions)) {
            biometricPromptHelper.authenticateWithFallback(
                activity, title, subtitle, description,
                fallbackOptions ?: emptyList(), cryptoObject
            )
        } else {
            biometricPromptHelper.authenticate(
                activity, title, subtitle, description, cancelText,
                allowDeviceCredentials, cryptoObject
            )
        }
    }

    private fun buildKeyResponse(publicKey: PublicKey, format: KeyFormat, decryptingKey: PublicKey? = null, authenticationType: AuthenticationType? = null): KeyCreationResult {
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
            authenticationType = authenticationType
        )
    }

    private fun buildSignatureResponse(signatureBytes: ByteArray, publicKey: PublicKey, format: SignatureFormat, keyFormat: KeyFormat, authenticationType: AuthenticationType): SignatureResult {
        val sigString = when (format) {
            SignatureFormat.BASE64, SignatureFormat.RAW -> android.util.Base64.encodeToString(signatureBytes, android.util.Base64.NO_WRAP)
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
