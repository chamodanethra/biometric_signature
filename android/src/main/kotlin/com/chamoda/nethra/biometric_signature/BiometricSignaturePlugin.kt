package com.chamoda.nethra.biometric_signature

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
const val USER_CANCELED = "USER_CANCELED"
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

  private fun createKeys(useStrongBox: Boolean, @NonNull result: MethodChannel.Result) {
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
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(-1) // Require authentication every time
        }

        if (useStrongBox && activity!!.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
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

      if (payload == null || !isValidUTF8(payload)) {
        result.error(INVALID_PAYLOAD, "Payload is required and must be valid UTF-8", null)
        return
      }
      val payloadBytes = payload.toByteArray(Charsets.UTF_8)

      val signature = Signature.getInstance("SHA256withRSA")
      val keyStore = KeyStore.getInstance("AndroidKeyStore")
      keyStore.load(null)
      val privateKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as PrivateKey
      signature.initSign(privateKey)
      val cryptoObject = BiometricPrompt.CryptoObject(signature)
      activity!!.setTheme(androidx.appcompat.R.style.Theme_AppCompat_Light_DarkActionBar)
      val executor = ContextCompat.getMainExecutor(activity!!)
      var resultReturned = false
      BiometricPrompt(activity!!, executor,
        object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(authResult)
            if (!resultReturned) {
              resultReturned = true
              val cryptoSignature = authResult.cryptoObject!!.signature!!
              cryptoSignature.update(payloadBytes)
              val signedString = Base64.encodeToString(cryptoSignature.sign(), Base64.DEFAULT)
                .replace("\r", "").replace("\n", "")
              result.success(signedString)
            }
          }
          override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            if (!resultReturned) {
              resultReturned = true
              when (errorCode) {
                BiometricPrompt.ERROR_NEGATIVE_BUTTON -> result.error(USER_CANCELED, errString.toString(), null)
                BiometricPrompt.ERROR_USER_CANCELED -> result.error(USER_CANCELED, errString.toString(), null)
                BiometricPrompt.ERROR_LOCKOUT -> result.error("LOCKOUT", errString.toString(), null)
                BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> result.error("LOCKOUT_PERMANENT", errString.toString(), null)
                else -> result.error("AUTH_ERROR", errString.toString(), null)
              }
            }
          }
        }).authenticate(PromptInfo.Builder()
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .setNegativeButtonText(cancelButtonText)
        .setTitle(promptMessage)
        .build(), cryptoObject)
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
