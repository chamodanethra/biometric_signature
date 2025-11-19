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
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.Date
import java.util.TimeZone
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal object Errors {
    const val AUTH_FAILED = "AUTH_FAILED"
    const val INVALID_PAYLOAD = "INVALID_PAYLOAD"
}

internal object Aliases {
    const val BIOMETRIC_KEY_ALIAS = "biometric_key"
}

private enum class KeyFormat {
    BASE64,
    PEM,
    RAW,
    HEX;

    companion object {
        fun from(raw: Any?): KeyFormat {
            val normalized = (raw as? String)?.uppercase(Locale.US)
            return when (normalized) {
                "PEM" -> PEM
                "RAW" -> RAW
                "HEX" -> HEX
                else -> BASE64
            }
        }
    }
}

private data class FormattedOutput(
    val value: Any,
    val format: KeyFormat,
    val pemLabel: String? = null,
)

private data class SigningSetup(
    val cryptoObject: BiometricPrompt.CryptoObject,
    val algorithm: String,
    val publicKey: PublicKey,
    val privateKey: PrivateKey,
)

class BiometricSignaturePlugin :
    FlutterPlugin,
    MethodCallHandler,
    ActivityAware {

    private lateinit var channel: MethodChannel
    private lateinit var appContext: Context
    private var activity: FlutterFragmentActivity? = null

    // ---- Structured concurrency for the plugin lifecycle ----
    private val pluginJob = SupervisorJob()
    private val exceptionHandler = CoroutineExceptionHandler { _, e ->
        android.util.Log.e("BiometricSignature", "Unhandled coroutine error", e)
    }
    private val pluginScope = CoroutineScope(Dispatchers.Main.immediate + pluginJob + exceptionHandler)

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext

        // Run handlers on a background TaskQueue (Flutter best practice for potentially heavy work)
        val queue = binding.binaryMessenger.makeBackgroundTaskQueue()
        channel = MethodChannel(
            binding.binaryMessenger,
            "biometric_signature",
            StandardMethodCodec.INSTANCE,
            queue
        )
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        pluginJob.cancel() // cancels all running coroutines
    }

    // ---- ActivityAware ----
    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FlutterFragmentActivity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        onDetachedFromActivity()
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        onAttachedToActivity(binding)
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    // ---- Method channel handler ----
    override fun onMethodCall(call: MethodCall, result: Result) {
        val act = activity
        if (act !is FlutterFragmentActivity) {
            result.error(
                "INCOMPATIBLE_ACTIVITY",
                "BiometricSignaturePlugin requires your app to use FlutterFragmentActivity",
                null
            )
            return
        }

        when (call.method) {
            "createKeys" -> {
                @Suppress("UNCHECKED_CAST")
                val args = call.arguments<Map<String, Any?>>() ?: emptyMap()
                val useDeviceCredentials = (args["useDeviceCredentials"] as? Boolean) == true
                val useEc = (args["useEc"] as? Boolean) == true
                val keyFormat = KeyFormat.from(args["keyFormat"])
                val setInvalidatedByBiometricEnrollment = args["setInvalidatedByBiometricEnrollment"] as Boolean

                pluginScope.launch {
                    try {
                        val payload = withContext(Dispatchers.IO) {
                                generateKeyMaterial(
                                    ctx = act,
                                    useEc = useEc,
                                    useDeviceCredentials = useDeviceCredentials,
                                    format = keyFormat,
                                    setInvalidatedByBiometricEnrollment = setInvalidatedByBiometricEnrollment,
                                )
                        }

                        withContext(Dispatchers.Main.immediate) { result.success(payload) }
                    } catch (t: Throwable) {
                        withContext(Dispatchers.Main.immediate) {
                            result.error(
                                Errors.AUTH_FAILED,
                                "Error generating keys: ${t.javaClass.simpleName}: ${t.message}",
                                t.stackTraceToString()
                            )
                        }
                    }
                }
            }

            "createSignature" -> {
                @Suppress("UNCHECKED_CAST")
                val options = call.arguments<Map<String, Any?>>() ?: emptyMap()
                val cancelButtonText = (options["cancelButtonText"] as? String) ?: "Cancel"
                val promptMessage = (options["promptMessage"] as? String) ?: "Authenticate"
                val payload = (options["payload"] as? String)
                val allowDeviceCredentials = when (val raw = options["allowDeviceCredentials"]) {
                    is Boolean -> raw
                    is String -> raw.equals("true", ignoreCase = true)
                    else -> false
                }
                val keyFormat = KeyFormat.from(options["keyFormat"])

                pluginScope.launch {
                    try {
                        if (payload == null || !isValidUTF8(payload)) {
                            withContext(Dispatchers.Main.immediate) {
                                result.error(Errors.INVALID_PAYLOAD, "Payload is required and must be valid UTF-8", null)
                            }
                            return@launch
                        }

                        // Load private/public key & create Signature/CryptoObject off main thread
                        val signingSetup = withContext(Dispatchers.IO) {
                            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                            val entry = keyStore.getEntry(Aliases.BIOMETRIC_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                                ?: throw IllegalStateException("Private key not found. Call createKeys() first.")
                            val privateKey = entry.privateKey
                            val publicKey = entry.certificate?.publicKey
                                ?: throw IllegalStateException("Public key not found for alias $Aliases.BIOMETRIC_KEY_ALIAS")
                            val sigAlgo = when (privateKey.algorithm.uppercase(Locale.US)) {
                                "EC" -> "SHA256withECDSA"
                                "RSA" -> "SHA256withRSA"
                                else -> throw IllegalStateException("Unsupported key algo: ${privateKey.algorithm}")
                            }
                            val signature = Signature.getInstance(sigAlgo).apply { initSign(privateKey) }
                            SigningSetup(
                                cryptoObject = BiometricPrompt.CryptoObject(signature),
                                algorithm = sigAlgo,
                                publicKey = publicKey,
                                privateKey = privateKey,
                            )
                        }

                        val authenticators =
                            if (allowDeviceCredentials && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                                        BiometricManager.Authenticators.DEVICE_CREDENTIAL
                            } else {
                                BiometricManager.Authenticators.BIOMETRIC_STRONG
                            }

                        val biometricManager = BiometricManager.from(act)
                        val can = biometricManager.canAuthenticate(authenticators)
                        if (can != BiometricManager.BIOMETRIC_SUCCESS) {
                            withContext(Dispatchers.Main.immediate) {
                                result.error(
                                    Errors.AUTH_FAILED,
                                    "Biometrics/Device Credentials not available (code: $can)",
                                    null
                                )
                            }
                            return@launch
                        }

                        activity!!.setTheme(androidx.appcompat.R.style.Theme_AppCompat_Light_DarkActionBar)

                        val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
                            .setTitle(promptMessage)
                            .setAllowedAuthenticators(authenticators)

                        if (!(allowDeviceCredentials && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)) {
                            // If device credential isn't allowed (or < API 30), we must show a negative button
                            promptInfoBuilder.setNegativeButtonText(cancelButtonText)
                        }

                        val promptInfo = promptInfoBuilder.build()
                        val cryptoObject = signingSetup.cryptoObject

                        // Show biometric prompt and await result (Main executor inside, suspension via continuation)
                        val authResult = authenticateWithBiometric(act, promptInfo, cryptoObject)

                        // Sign payload
                        val signatureBytes = withContext(Dispatchers.IO) {
                                val sig = authResult.cryptoObject?.signature
                                    ?: throw IllegalStateException("No signature object returned")
                                sig.update(payload.toByteArray(Charsets.UTF_8))
                                sig.sign()
                        }

                        val formattedSignature = formatValue(signatureBytes, keyFormat, "SIGNATURE")
                        val formattedPublicKey = formatValue(signingSetup.publicKey.encoded, keyFormat)
                        val response = hashMapOf<String, Any?>(
                            "publicKey" to formattedPublicKey.value,
                            "publicKeyFormat" to formattedPublicKey.format.name,
                            "signature" to formattedSignature.value,
                            "signatureFormat" to formattedSignature.format.name,
                            "algorithm" to signingSetup.privateKey.algorithm.uppercase(Locale.US),
                            "keySize" to keySizeBits(signingSetup.publicKey),
                            "timestamp" to isoTimestamp(),
                            "keyFormat" to keyFormat.name,
                        )
                        formattedPublicKey.pemLabel?.let { response["publicKeyPemLabel"] = it }
                        formattedSignature.pemLabel?.let { response["signaturePemLabel"] = it }

                        withContext(Dispatchers.Main.immediate) { result.success(response) }
                    } catch (t: Throwable) {
                        if (t is CancellationException) throw t
                        withContext(Dispatchers.Main.immediate) {
                            result.error(Errors.AUTH_FAILED, "Error generating signature: ${t.message}", null)
                        }
                    }
                }
            }

            "deleteKeys" -> {
                pluginScope.launch {
                    try {
                        val deleted = withContext(Dispatchers.IO) { deleteBiometricKey() }
                        withContext(Dispatchers.Main.immediate) {
                            if (deleted) result.success(true)
                            else result.error(Errors.AUTH_FAILED, "Error deleting the biometric key", null)
                        }
                    } catch (t: Throwable) {
                        withContext(Dispatchers.Main.immediate) {
                            result.error(Errors.AUTH_FAILED, "Error deleting the biometric key: ${t.message}", null)
                        }
                    }
                }
            }

            "biometricAuthAvailable" -> {
                pluginScope.launch {
                    val actNonNull = activity!!
                    val biometricManager = BiometricManager.from(actNonNull)
                    val canAuthenticate =
                        biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

                    fun processBiometricString(rawString: String): String {
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
                        val otherBiometrics = otherString.filter { rawString.contains(it, ignoreCase = true) }

                        return if (identifiedFingerprint) {
                            if (otherBiometrics.isEmpty()) "fingerprint" else "biometric"
                        } else {
                            if (otherBiometrics.size == 1 && otherBiometrics[0] != ",") otherBiometrics[0] else "biometric"
                        }
                    }

                    if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
                        val label = BiometricManager.from(actNonNull)
                            .getStrings(BiometricManager.Authenticators.BIOMETRIC_STRONG)?.buttonLabel
                            .toString()
                        withContext(Dispatchers.Main.immediate) {
                            result.success(processBiometricString(label))
                        }
                    } else {
                        val errorString = when (canAuthenticate) {
                            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "BIOMETRIC_ERROR_NO_HARDWARE"
                            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "BIOMETRIC_ERROR_HW_UNAVAILABLE"
                            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "BIOMETRIC_ERROR_NONE_ENROLLED"
                            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED"
                            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> "BIOMETRIC_ERROR_UNSUPPORTED"
                            BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> "BIOMETRIC_STATUS_UNKNOWN"
                            else -> "NO_BIOMETRICS"
                        }
                        withContext(Dispatchers.Main.immediate) {
                            result.success("none, $errorString")
                        }
                    }
                }
            }

            "biometricKeyExists" -> {
                val checkValidity = (call.arguments<Boolean?>()) == true
                pluginScope.launch {
                    val exists = withContext(Dispatchers.IO) { doesBiometricKeyExist(checkValidity) }
                    withContext(Dispatchers.Main.immediate) { result.success(exists) }
                }
            }

            else -> result.notImplemented()
        }
    }

    // ---------- Suspend helpers ----------

    private suspend fun authenticateWithBiometric(
        activity: FragmentActivity,
        promptInfo: BiometricPrompt.PromptInfo,
        cryptoObject: BiometricPrompt.CryptoObject?
    ): BiometricPrompt.AuthenticationResult = suspendCancellableCoroutine { cont ->
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (cont.isActive) cont.resumeWithException(
                    RuntimeException("$errString (code: $errorCode)")
                )
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (cont.isActive) cont.resume(result)
            }

            override fun onAuthenticationFailed() {
                // ignore; user can retry; final result comes via error/succeeded
            }
        }
        val prompt = BiometricPrompt(activity, executor, callback)
        if (cryptoObject != null) prompt.authenticate(promptInfo, cryptoObject)
        else prompt.authenticate(promptInfo)

        cont.invokeOnCancellation {
            // No direct cancel API to dismiss system prompt programmatically.
            // If you add your own UI layer in the future, dismiss it here.
        }
    }

    // ---------- Keystore helpers ----------

    @Throws(Exception::class)
    private fun generateKeyMaterial(
        ctx: Context,
        useEc: Boolean,
        useDeviceCredentials: Boolean,
        format: KeyFormat,
        setInvalidatedByBiometricEnrollment: Boolean,
    ): Map<String, Any?> {
        val keyPair = generateKeyPair(
            ctx = ctx,
            useEc = useEc,
            useDeviceCredentials = useDeviceCredentials,
            setInvalidatedByBiometricEnrollment = setInvalidatedByBiometricEnrollment,
        )
        val publicKey = keyPair.public
        val formatted = formatValue(publicKey.encoded, format)
        val response = hashMapOf<String, Any?>(
            "publicKey" to formatted.value,
            "publicKeyFormat" to formatted.format.name,
            "algorithm" to publicKey.algorithm.uppercase(Locale.US),
            "keySize" to keySizeBits(publicKey),
            "keyFormat" to format.name,
        )
        formatted.pemLabel?.let { response["publicKeyPemLabel"] = it }
        return response
    }

    @Throws(Exception::class)
    private fun generateKeyPair(
        ctx: Context,
        useEc: Boolean,
        useDeviceCredentials: Boolean,
        setInvalidatedByBiometricEnrollment: Boolean,
    ): KeyPair {
        deleteBiometricKey()

        val algorithm = if (useEc) KeyProperties.KEY_ALGORITHM_EC else KeyProperties.KEY_ALGORITHM_RSA
        val kpg = KeyPairGenerator.getInstance(algorithm, "AndroidKeyStore")

        val builder = KeyGenParameterSpec.Builder(
            Aliases.BIOMETRIC_KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN
        ).setDigests(KeyProperties.DIGEST_SHA256)

        if (useEc) {
            builder.setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        } else {
            builder.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            builder.setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
        }

        builder.setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val allowed = if (useDeviceCredentials)
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            else
                KeyProperties.AUTH_BIOMETRIC_STRONG
            builder.setUserAuthenticationParameters(0, allowed)
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(setInvalidatedByBiometricEnrollment)
        }

        if (ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
        ) {
            try {
                builder.setIsStrongBoxBacked(true)
            } catch (_: StrongBoxUnavailableException) {
                builder.setIsStrongBoxBacked(false)
            }
        }

        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    private fun isValidUTF8(payload: String): Boolean = try {
        payload.toByteArray(Charsets.UTF_8); true
    } catch (_: Exception) {
        false
    }

    private fun formatValue(bytes: ByteArray, format: KeyFormat, pemLabel: String = "PUBLIC KEY"): FormattedOutput {
        return when (format) {
            KeyFormat.BASE64 -> FormattedOutput(
                value = Base64.encodeToString(bytes, Base64.NO_WRAP),
                format = KeyFormat.BASE64,
            )
            KeyFormat.HEX -> FormattedOutput(
                value = bytes.joinToString(separator = "") { String.format("%02x", it) },
                format = KeyFormat.HEX,
            )
            KeyFormat.RAW -> FormattedOutput(
                value = bytes,
                format = KeyFormat.RAW,
            )
            KeyFormat.PEM -> {
                val base64 = Base64.encodeToString(bytes, Base64.NO_WRAP)
                val body = chunkBase64(base64)
                val pem = "-----BEGIN $pemLabel-----\n$body\n-----END $pemLabel-----"
                FormattedOutput(value = pem, format = KeyFormat.PEM, pemLabel = pemLabel)
            }
        }
    }

    private fun chunkBase64(base64: String, chunk: Int = 64): String {
        if (base64.isEmpty()) return base64
        val builder = StringBuilder()
        var index = 0
        while (index < base64.length) {
            val end = minOf(index + chunk, base64.length)
            builder.append(base64.substring(index, end)).append('\n')
            index = end
        }
        return builder.toString().trimEnd()
    }

    private fun keySizeBits(publicKey: PublicKey): Int {
        return when (publicKey) {
            is RSAPublicKey -> publicKey.modulus.bitLength()
            is ECPublicKey -> publicKey.params.order.bitLength()
            else -> 0
        }
    }

    private fun isoTimestamp(): String {
        val formatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        formatter.timeZone = TimeZone.getTimeZone("UTC")
        return formatter.format(Date())
    }

    private fun doesBiometricKeyExist(checkValidity: Boolean = false): Boolean {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (!ks.containsAlias(Aliases.BIOMETRIC_KEY_ALIAS)) return false
            if (!checkValidity) return true
            val privateKey = ks.getKey(Aliases.BIOMETRIC_KEY_ALIAS, null) as PrivateKey
            try {
                Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }; true
            } catch (_: Exception) {
                Signature.getInstance("SHA256withRSA").apply { initSign(privateKey) }; true
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun deleteBiometricKey(): Boolean = try {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.deleteEntry(Aliases.BIOMETRIC_KEY_ALIAS)
        true
    } catch (_: Exception) {
        false
    }
}
