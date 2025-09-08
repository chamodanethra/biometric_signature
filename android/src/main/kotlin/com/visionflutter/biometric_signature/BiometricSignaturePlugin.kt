package com.visionflutter.biometric_signature

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.PromptInfo
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*

const val AUTH_FAILED = "AUTH_FAILED"
const val INVALID_PAYLOAD = "INVALID_PAYLOAD"
const val BIOMETRIC_KEY_ALIAS = "biometric_key"

/** BiometricSignaturePlugin */
class BiometricSignaturePlugin : FlutterPlugin, MethodCallHandler, ActivityAware {
    private lateinit var channel: MethodChannel
    private lateinit var appContext: Context
    private var activity: FlutterFragmentActivity? = null

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

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        appContext = flutterPluginBinding.applicationContext
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "biometric_signature")
        channel.setMethodCallHandler(this)

    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        if (activity !is FlutterFragmentActivity) {
            result.error(
                "INCOMPATIBLE_ACTIVITY",
                "BiometricSignaturePlugin requires your app to use FlutterFragmentActivity",
                null
            )
            return
        }
        when (call.method) {
            "createKeys" -> {
                createKeys(call.arguments()!!, result)
            }

            "createSignature" -> {
                createSignature(call.arguments(), result)
            }

            "deleteKeys" -> {
                deleteKeys(result)
            }

            "biometricAuthAvailable" -> {
                biometricAuthAvailable(result)
            }

            "biometricKeyExists" -> {
                biometricKeyExists(call.arguments()!!, result)
            }

            else -> {
                result.notImplemented()
            }
        }
    }

    private fun createKeys(arguments: Map<String, Any>, result: Result) {
        val useDeviceCredentials = arguments["useDeviceCredentials"] as Boolean
        val useEc = arguments["useEc"] as Boolean

        try {
            deleteBiometricKey()
            val keyPairGenerator: KeyPairGenerator =
                KeyPairGenerator.getInstance(
                    if (useEc) KeyProperties.KEY_ALGORITHM_EC else KeyProperties.KEY_ALGORITHM_RSA,
                    "AndroidKeyStore"
                )


            val builder =
                KeyGenParameterSpec.Builder(BIOMETRIC_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)

            if (useEc)
                builder.setAlgorithmParameterSpec(
                    // supported strings is hard to figure out
                    ECGenParameterSpec("secp256r1")
                )
            else
                builder
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setAlgorithmParameterSpec(
                        RSAKeyGenParameterSpec(
                            2048,
                            RSAKeyGenParameterSpec.F4
                        )
                    )


            builder.setUserAuthenticationRequired(true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                if (useDeviceCredentials) {
                    builder.setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    )
                } else {
                    builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                }
            } else {
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }

            if (activity!!.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    try {
                        builder.setIsStrongBoxBacked(true)
                    } catch (e: StrongBoxUnavailableException) {
                        // Fallback to TEE
                        builder.setIsStrongBoxBacked(false)
                    }
                }
            }

            keyPairGenerator.initialize(builder.build())
            val keyPair: KeyPair = keyPairGenerator.generateKeyPair()
            val publicKey: PublicKey = keyPair.public
            val encodedPublicKey: ByteArray = publicKey.encoded
            var publicKeyString = Base64.encodeToString(encodedPublicKey, Base64.DEFAULT)
            publicKeyString = publicKeyString.replace("\r", "").replace("\n", "")
            result.success(publicKeyString)
        } catch (e: Exception) {
            result.error(
                AUTH_FAILED,
                "Error generating public-private keys: ${e.javaClass.name}: ${e.message}",
                e.stackTraceToString()
            )
        }
    }

    private fun createSignature(
        options: MutableMap<String, String>?,
        result: Result
    ) {
        try {
            val cancelButtonText = options?.get("cancelButtonText") ?: "Cancel"
            val promptMessage = options?.get("promptMessage") ?: "Welcome"
            val payload = options?.get("payload")
            val allowDeviceCredentials =
                options?.get("allowDeviceCredentials")?.toBoolean() ?: false

            if (payload == null || !isValidUTF8(payload)) {
                result.error(INVALID_PAYLOAD, "Payload is required and must be valid UTF-8", null)
                return
            }

            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val privateKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as PrivateKey
            val algo = when (privateKey.algorithm) {
                "EC"  -> "SHA256withECDSA"
                "RSA" -> "SHA256withRSA"
                else  -> return result.error(AUTH_FAILED, "Unsupported key algo: ${privateKey.algorithm}", null)
            }
            val signature = Signature.getInstance(algo).apply { initSign(privateKey) }
            val cryptoObject = signature?.let { BiometricPrompt.CryptoObject(it) }

            val biometricManager = BiometricManager.from(activity!!)
            val canAuthenticate: Int =
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                    biometricManager.canAuthenticate(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                                BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    )
                } else {
                    // For older devices, we just check if BIOMETRIC is available.
                    biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                }

            if (canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS) {
                result.error(AUTH_FAILED, "Biometrics/Device Credentials not available", null)
                return
            }

            activity!!.setTheme(androidx.appcompat.R.style.Theme_AppCompat_Light_DarkActionBar)

            val executor = ContextCompat.getMainExecutor(activity!!)
            val biometricPrompt = BiometricPrompt(
                activity!!,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        result.error(AUTH_FAILED, "$errString (code: $errorCode)", null)
                    }

                    override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(authResult)
                        try {
                            val returnedCryptoObject = authResult.cryptoObject
                            val signatureObj = returnedCryptoObject?.signature
                            if (signatureObj == null) {
                                result.error(AUTH_FAILED, "No signature object returned", null)
                                return
                            }
                            signatureObj.update(payload.toByteArray(Charsets.UTF_8))
                            val signatureBytes = signatureObj.sign()
                            val signatureBase64 = Base64.encodeToString(
                                signatureBytes,
                                Base64.NO_WRAP
                            )
                            result.success(signatureBase64)
                        } catch (e: Exception) {
                            result.error(
                                AUTH_FAILED,
                                "Error signing data: ${e.localizedMessage}",
                                null
                            )
                        }
                    }
                }
            )

            val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
                .setTitle(promptMessage)
            if (allowDeviceCredentials && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                // If using device credentials fallback, do not set negative button text
                promptInfoBuilder.setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
            } else {
                // Otherwise, fallback to only BIOMETRIC_STRONG, show negative button
                promptInfoBuilder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                promptInfoBuilder.setNegativeButtonText(cancelButtonText)
            }
            val promptInfo = promptInfoBuilder.build()
            if (cryptoObject != null) {
                biometricPrompt.authenticate(promptInfo, cryptoObject)
            } else {
                // If we don't have a real signature-based approach, just do:
                biometricPrompt.authenticate(promptInfo)
            }
        } catch (e: Exception) {
            result.error(AUTH_FAILED, "Error generating signature: ${e.message}", null)
        }
    }

    private fun isValidUTF8(payload: String): Boolean {
        return try {
            payload.toByteArray(Charsets.UTF_8)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun deleteKeys(result: MethodChannel.Result) {
        if (doesBiometricKeyExist()) {
            val resultBoolean = deleteBiometricKey()
            if (resultBoolean) {
                result.success(resultBoolean)
            } else {
                result.error(
                    AUTH_FAILED,
                    "Error deleting biometric key from keystore", null
                )
            }
        } else {
            result.success(false)
        }
    }

    private fun biometricKeyExists(checkValidity: Boolean, result: MethodChannel.Result) {
        try {
            val biometricKeyExists = doesBiometricKeyExist(checkValidity)
            result.success(biometricKeyExists)
        } catch (e: Exception) {
            result.error(
                AUTH_FAILED,
                "Error checking if biometric key exists: ${e.message}", null
            )
        }
    }

    private fun biometricAuthAvailable(result: MethodChannel.Result) {
        fun processBiometricString(rawString: String): String {

            var identifiedFingerprint = false
            val pm = appContext.packageManager

            // Fingerprint (API 23+): check hardware + (if possible) enrollment
            if (pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {        // feature flag
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val fm = appContext.getSystemService(FingerprintManager::class.java)
                    val enrolled = try {
                        fm?.hasEnrolledFingerprints() == true
                    }   // may require USE_BIOMETRIC
                    catch (_: SecurityException) {
                        true
                    }          // fall back to assuming enrolled
                    identifiedFingerprint = fm?.isHardwareDetected == true && enrolled
                }
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
                    return  otherBiometrics[0]
                } else {
                    return "biometric"
                }
            }
        }

        val biometricManager = BiometricManager.from(activity!!)
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
            val errorString = when (canAuthenticate) {
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


    private fun doesBiometricKeyExist(checkValidity: Boolean = false): Boolean {
        try {
            val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (!keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)) {
                return false
            }
            if (!checkValidity) {
                return true
            }
            val privateKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as PrivateKey
            try {
                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initSign(privateKey)
                return true
            } catch (e: Exception) {
                val signature = Signature.getInstance("SHA256withRSA")
                signature.initSign(privateKey)
                return true
            }
        } catch (e: Exception) {
            return false
        }
    }

    private fun deleteBiometricKey(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            keyStore.deleteEntry(BIOMETRIC_KEY_ALIAS)
            true
        } catch (e: java.lang.Exception) {
            false
        }
    }
}
