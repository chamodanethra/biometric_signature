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
import kotlinx.coroutines.*
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Locale
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

const val AUTH_FAILED = "AUTH_FAILED"
const val INVALID_PAYLOAD = "INVALID_PAYLOAD"
const val BIOMETRIC_KEY_ALIAS = "biometric_key"

class BiometricSignaturePlugin :
    FlutterPlugin,
    MethodCallHandler,
    ActivityAware {

    private lateinit var channel: MethodChannel
    private lateinit var appContext: Context
    private var activity: FlutterFragmentActivity? = null

    // Coroutine scope tied to plugin lifecycle
    private val pluginScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FlutterFragmentActivity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        onAttachedToActivity(binding)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        onDetachedFromActivity()
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, "biometric_signature")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        pluginScope.cancel() // cancel any running coroutines
    }

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
                pluginScope.launch {
                    try {
                        val useDeviceCredentials = (args["useDeviceCredentials"] as? Boolean) == true
                        val useEc = (args["useEc"] as? Boolean) == true
                        val publicKeyB64 = withContext(Dispatchers.IO) {
                            generateKeyPairAndReturnPublicKeyB64(act, useEc, useDeviceCredentials)
                        }
                        result.success(publicKeyB64)
                    } catch (t: Throwable) {
                        result.error(
                            AUTH_FAILED,
                            "Error generating public-private keys: ${t.javaClass.simpleName}: ${t.message}",
                            t.stackTraceToString()
                        )
                    }
                }
            }

            "createSignature" -> {
                @Suppress("UNCHECKED_CAST")
                val options = call.arguments<Map<String, Any?>>() ?: emptyMap()
                pluginScope.launch {
                    try {
                        val cancelButtonText = (options["cancelButtonText"] as? String) ?: "Cancel"
                        val promptMessage = (options["promptMessage"] as? String) ?: "Authenticate"
                        val payload = (options["payload"] as? String)
                        val allowDeviceCredentials = (options["allowDeviceCredentials"] as? Boolean) == true

                        if (payload == null || !isValidUTF8(payload)) {
                            result.error(INVALID_PAYLOAD, "Payload is required and must be valid UTF-8", null)
                            return@launch
                        }

                        // Load private key & create Signature/CryptoObject off main thread
                        val (algo, cryptoObject) = withContext(Dispatchers.IO) {
                            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                            val privateKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as? PrivateKey
                                ?: throw IllegalStateException("Private key not found. Call createKeys() first.")
                            val sigAlgo = when (privateKey.algorithm.uppercase(Locale.US)) {
                                "EC" -> "SHA256withECDSA"
                                "RSA" -> "SHA256withRSA"
                                else -> throw IllegalStateException("Unsupported key algo: ${privateKey.algorithm}")
                            }
                            val signature = Signature.getInstance(sigAlgo).apply { initSign(privateKey) }
                            sigAlgo to BiometricPrompt.CryptoObject(signature)
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
                            result.error(AUTH_FAILED, "Biometrics/Device Credentials not available (code: $can)", null)
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

                        // Show prompt & await result on main thread
                        val authResult = authenticateWithBiometric(act, promptInfo, cryptoObject)

                        // Sign on IO
                        val signatureBase64 = withContext(Dispatchers.IO) {
                            val sig = authResult.cryptoObject?.signature
                                ?: throw IllegalStateException("No signature object returned")
                            sig.update(payload.toByteArray(Charsets.UTF_8))
                            val signed = sig.sign()
                            Base64.encodeToString(signed, Base64.NO_WRAP)
                        }

                        result.success(signatureBase64)
                    } catch (t: Throwable) {
                        result.error(AUTH_FAILED, "Error generating signature: ${t.message}", null)
                    }
                }
            }

            "deleteKeys" -> {
                pluginScope.launch {
                    val deleted = withContext(Dispatchers.IO) { deleteBiometricKey() }
                    if (deleted) result.success(true) else
                        result.error(AUTH_FAILED, "Error deleting biometric key from keystore", null)
                }
            }

            "biometricAuthAvailable" -> {
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
                    val otherBiometrics =
                        otherString.filter { rawString.contains(it, ignoreCase = true) }

                    if (identifiedFingerprint) {
                        if (otherBiometrics.size == 0) {
                            return "fingerprint"
                        } else {
                            return "biometric"
                        }
                    } else {
                        if (otherBiometrics.size == 1 && otherBiometrics[0] != ",") {
                            return otherBiometrics[0]
                        } else {
                            return "biometric"
                        }
                    }
                }

                pluginScope.launch {
                    val biometricManager = BiometricManager.from(act!!)
                    val canAuthenticate =
                        biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

                    if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
                        result.success(
                            processBiometricString(
                                BiometricManager.from(activity!!)
                                    .getStrings(BiometricManager.Authenticators.BIOMETRIC_STRONG)?.buttonLabel.toString()
                            )
                        )
                    } else {
                        var errorString = when (canAuthenticate) {
                            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "BIOMETRIC_ERROR_NO_HARDWARE"
                            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "BIOMETRIC_ERROR_HW_UNAVAILABLE"
                            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "BIOMETRIC_ERROR_NONE_ENROLLED"
                            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED"
                            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> "BIOMETRIC_ERROR_UNSUPPORTED"
                            BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> "BIOMETRIC_STATUS_UNKNOWN"
                            else -> "NO_BIOMETRICS"
                        }
                        result.success("none, $errorString")
                    }
                }
            }

            "biometricKeyExists" -> {
                val checkValidity = (call.arguments<Boolean?>()) == true
                pluginScope.launch {
                    val exists = withContext(Dispatchers.IO) { doesBiometricKeyExist(checkValidity) }
                    result.success(exists)
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
        if (cryptoObject != null) {
            prompt.authenticate(promptInfo, cryptoObject)
        } else {
            prompt.authenticate(promptInfo)
        }
        // No direct programmatic cancel API; if coroutine cancels, we just drop the result.
        cont.invokeOnCancellation {
            // Optionally log or dismiss UI if you manage your own dialog layer.
        }
    }

    // ---------- Keystore helpers ----------

    @Throws(Exception::class)
    private fun generateKeyPairAndReturnPublicKeyB64(
        ctx: Context,
        useEc: Boolean,
        useDeviceCredentials: Boolean
    ): String {
        deleteBiometricKey()

        val algorithm = if (useEc) KeyProperties.KEY_ALGORITHM_EC else KeyProperties.KEY_ALGORITHM_RSA
        val kpg = KeyPairGenerator.getInstance(algorithm, "AndroidKeyStore")

        val builder = KeyGenParameterSpec.Builder(
            BIOMETRIC_KEY_ALIAS,
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
        val kp: KeyPair = kpg.generateKeyPair()
        val publicKey: PublicKey = kp.public
        val raw = publicKey.encoded
        return Base64.encodeToString(raw, Base64.NO_WRAP)
    }

    private fun isValidUTF8(payload: String): Boolean = try {
        payload.toByteArray(Charsets.UTF_8); true
    } catch (_: Exception) {
        false
    }

    private fun doesBiometricKeyExist(checkValidity: Boolean = false): Boolean {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (!ks.containsAlias(BIOMETRIC_KEY_ALIAS)) return false
            if (!checkValidity) return true
            val privateKey = ks.getKey(BIOMETRIC_KEY_ALIAS, null) as PrivateKey
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
        ks.deleteEntry(BIOMETRIC_KEY_ALIAS)
        true
    } catch (_: Exception) {
        false
    }
}
