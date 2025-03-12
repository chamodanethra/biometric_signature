package com.visionflutter.biometric_signature

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.annotation.NonNull
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
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*

const val AUTH_FAILED = "AUTH_FAILED"
const val INVALID_PAYLOAD = "INVALID_PAYLOAD"
const val BIOMETRIC_KEY_ALIAS = "biometric_key"
/** BiometricSignaturePlugin */
class BiometricSignaturePlugin : FlutterPlugin, MethodCallHandler, ActivityAware {
  private lateinit var channel: MethodChannel
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

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "biometric_signature")
    channel.setMethodCallHandler(this)

  }
  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    if (activity !is FlutterFragmentActivity || activity == null) {
      result.error("INCOMPATIBLE_ACTIVITY", "BiometricSignaturePlugin requires your app to use FlutterFragmentActivity", null)
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

  private fun createKeys(config: Map<String, Any>, @NonNull result: MethodChannel.Result) {
    val useDeviceCredentials = config["useDeviceCredentials"] as Boolean
    val enforceBiometric = config["enforceBiometric"] as Boolean
    @Suppress("UNCHECKED_CAST")
    val options = config["options"] as? Map<String, String>

    if (enforceBiometric) {
      val cancelButtonText = options?.get("cancelButtonText") ?: "Cancel"
      val promptMessage = options?.get("promptMessage") ?: "Authenticate"
      
      promptBiometricAuth(
        promptMessage = promptMessage,
        cancelButtonText = cancelButtonText,
        allowDeviceCredentials = false,
        cryptoObject = null,
        onSuccess = { _ -> proceedWithKeyCreation(useDeviceCredentials, result) },
        onError = { _, errString -> result.error(AUTH_FAILED, "Biometric authentication failed: $errString", null) }
      )
    } else {
      proceedWithKeyCreation(useDeviceCredentials, result)
    }
  }

  private fun proceedWithKeyCreation(useDeviceCredentials: Boolean, result: MethodChannel.Result) {
    try {
      deleteBiometricKey()
      val keyPairGenerator: KeyPairGenerator =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")

      val builder = KeyGenParameterSpec.Builder(BIOMETRIC_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        .setAlgorithmParameterSpec(
          RSAKeyGenParameterSpec(
            2048,
            RSAKeyGenParameterSpec.F4
          )
        )
        .setUserAuthenticationRequired(true)

      if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
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
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                try {
                    println("Attempting to use StrongBox")
                    builder.setIsStrongBoxBacked(true)
                } catch (e: StrongBoxUnavailableException) {
                    println("StrongBox unavailable: ${e.message}")
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

  private fun createSignature(options: MutableMap<String, String>?, @NonNull result: MethodChannel.Result) {
    try {
      val cancelButtonText = options?.get("cancelButtonText") ?: "Cancel"
      val promptMessage = options?.get("promptMessage") ?: "Welcome"
      val payload = options?.get("payload")
      val allowDeviceCredentials = options?.get("allowDeviceCredentials")?.toBoolean() ?: false

      if (payload == null || !isValidUTF8(payload)) {
        result.error(INVALID_PAYLOAD, "Payload is required and must be valid UTF-8", null)
        return
      }

       val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
       val privateKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as? PrivateKey
       val signature = Signature.getInstance("SHA256withRSA").apply {
           initSign(privateKey)
       }
      val cryptoObject = signature?.let { BiometricPrompt.CryptoObject(it) }

      promptBiometricAuth(
        promptMessage = promptMessage,
        cancelButtonText = cancelButtonText,
        allowDeviceCredentials = allowDeviceCredentials,
        cryptoObject = cryptoObject,
        onSuccess = { authResult ->
          try {
            val returnedCryptoObject = authResult.cryptoObject
            val signatureObj = returnedCryptoObject?.signature
            if (signatureObj == null) {
              result.error(AUTH_FAILED, "No signature object returned", null)
              return@promptBiometricAuth
            }
            signatureObj.update(payload.toByteArray(Charsets.UTF_8))
            val signatureBytes = signatureObj.sign()
            val signatureBase64 = Base64.encodeToString(
              signatureBytes,
              Base64.NO_WRAP
            )
            result.success(signatureBase64)
          } catch (e: Exception) {
            result.error(AUTH_FAILED, "Error signing data: ${e.localizedMessage}", null)
          }
        },
        onError = { errorCode, errString ->
          result.error(AUTH_FAILED, "$errString (code: $errorCode)", null)
        }
      )
    } catch (e: Exception) {
      result.error(AUTH_FAILED, "Error generating signature: ${e.message}", null)
    }
  }

  private fun promptBiometricAuth(
    promptMessage: String,
    cancelButtonText: String,
    allowDeviceCredentials: Boolean = false,
    cryptoObject: BiometricPrompt.CryptoObject? = null,
    onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
    onError: (Int, CharSequence) -> Unit
  ) {
    try {
      val biometricManager = BiometricManager.from(activity!!)
      val canAuthenticate: Int = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
        biometricManager.canAuthenticate(
          BiometricManager.Authenticators.BIOMETRIC_STRONG or
            (if (allowDeviceCredentials) BiometricManager.Authenticators.DEVICE_CREDENTIAL else 0)
        )
      } else {
        // For older devices, we just check if BIOMETRIC is available.
        biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      }

      if (canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS) {
        onError(-1, "Biometrics/Device Credentials not available")
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
            onError(errorCode, errString)
          }
          
          override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(authResult)
            onSuccess(authResult)
          }
          
          override fun onAuthenticationFailed() {
            super.onAuthenticationFailed()
            onError(-2, "Authentication failed")
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
      onError(-3, "Error in biometric prompt: ${e.message ?: "Unknown error"}")
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

  private fun deleteKeys(@NonNull result: MethodChannel.Result) {
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

  private fun biometricKeyExists(checkValidity: Boolean, @NonNull result: MethodChannel.Result) {
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

  private fun biometricAuthAvailable(@NonNull result: MethodChannel.Result) {
    fun processBiometricString(rawString: String): String {
      val androidBiometrics = listOf("fingerprint", "face", "iris")
      val biometricsList = androidBiometrics.filter { rawString.contains(it, ignoreCase = true) }

      return if (biometricsList.size == 1) biometricsList[0] else "biometric"
    }

    val biometricManager = BiometricManager.from(activity!!)
    val canAuthenticate = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

    if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
      result.success(processBiometricString(
        BiometricManager.from(activity!!)
          .getStrings(BiometricManager.Authenticators.BIOMETRIC_STRONG)?.buttonLabel.toString()
        ))
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


  private fun doesBiometricKeyExist(checkValidity: Boolean = false): Boolean {
    try {
      val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
      keyStore.load(null)
      if (!keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)) {
        return false
      }
      if (!checkValidity) {
        return  true
      }
      val signature = Signature.getInstance("SHA256withRSA")
      val privateKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as PrivateKey
      signature.initSign(privateKey)
      return true
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