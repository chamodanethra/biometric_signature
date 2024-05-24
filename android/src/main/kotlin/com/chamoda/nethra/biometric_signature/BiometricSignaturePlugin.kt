package com.chamoda.nethra.biometric_signature

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.*
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*

const val BIOMETRIC_KEY_ALIAS= "biometric_key"

/** BiometricSignaturePlugin */
class BiometricSignaturePlugin : FlutterPlugin, MethodCallHandler, ActivityAware {
  private lateinit var channel: MethodChannel
  private lateinit var activity: FlutterFragmentActivity
  private lateinit var binaryMessenger: BinaryMessenger

  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    this.activity = binding.activity as FlutterFragmentActivity
    channel = MethodChannel(binaryMessenger, "biometric_signature")
    channel.setMethodCallHandler(this)
  }

  override fun onDetachedFromActivityForConfigChanges() {
  }

  override fun onDetachedFromActivity() {
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
  }

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    binaryMessenger = flutterPluginBinding.binaryMessenger
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    when (call.method) {
      "createKeys" -> {
        createKeys(result)
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
        biometricKeyExists(result)
      }
      else -> {
        result.notImplemented()
      }
    }
  }

  private fun createKeys(@NonNull result: MethodChannel.Result) {
    try {
      deleteBiometricKey()
      val keyPairGenerator: KeyPairGenerator =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
      val keyGenParameterSpec: KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(BIOMETRIC_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
          .setDigests(KeyProperties.DIGEST_SHA256)
          .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
          .setAlgorithmParameterSpec(
            RSAKeyGenParameterSpec(
              2048,
              RSAKeyGenParameterSpec.F4
            )
          )
          .setUserAuthenticationRequired(true)
          .build()
      keyPairGenerator.initialize(keyGenParameterSpec)
      val keyPair: KeyPair = keyPairGenerator.generateKeyPair()
      val publicKey: PublicKey = keyPair.public
      val encodedPublicKey: ByteArray = publicKey.encoded
      var publicKeyString =
        Base64.encodeToString(encodedPublicKey, Base64.DEFAULT)
      publicKeyString = publicKeyString.replace("\r", "").replace("\n", "")
      result.success(publicKeyString)

    } catch (e: Exception) {
      result.error(
        "AUTHFAILED",
        "Error generating public private keys", null
      )
    }
  }

  private fun createSignature(options: MutableMap<String, String>?, @NonNull result: MethodChannel.Result) {
    try {
      val cancelButtonText = options?.get("cancelButtonText") ?: "Cancel"
      val promptMessage = options?.get("promptMessage") ?: "Welcome"
      val rawPayload =  options?.get("payload") ?: "arhten adomahc"
      val payload = Base64.encodeToString(rawPayload.toByteArray(Charsets.UTF_8), Base64.DEFAULT)
      val signature = Signature.getInstance("SHA256withRSA")
      val keyStore = KeyStore.getInstance("AndroidKeyStore")
      keyStore.load(null)
      val privateKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as PrivateKey
      signature.initSign(privateKey)
      val cryptoObject = BiometricPrompt.CryptoObject(signature)
      val executor = ContextCompat.getMainExecutor(activity)
      BiometricPrompt(activity, executor,
        object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(authResult)
            val cryptoSignature = authResult.cryptoObject!!.signature!!
            cryptoSignature.update(payload.toByteArray())
            val signedString = Base64.encodeToString(cryptoSignature.sign(), Base64.DEFAULT)
              .replace("\r", "").replace("\n", "")
            result.success(signedString)
          }

          override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON || errorCode == BiometricPrompt.ERROR_USER_CANCELED) {
              result.error("USERCANCEL", "userCancel", null)
            } else {
              result.error("$errorCode", errString.toString(), null)
            }
          }
        }).authenticate(PromptInfo.Builder()
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .setNegativeButtonText(cancelButtonText)
        .setTitle(promptMessage)
        .build(), cryptoObject)
    } catch (e: Exception) {
      result.error("AUTHFAILED", "Error generating signature: ${e.message}", null)
    }
  }

  private fun deleteKeys(@NonNull result: MethodChannel.Result) {
    if (doesBiometricKeyExist()) {
      val resultBoolean = deleteBiometricKey()
      if (resultBoolean) {
        result.success(resultBoolean)
      } else {
        result.error(
          "AUTHFAILED",
          "Error deleting biometric key from keystore", null
        )
      }
    } else {
      result.success(false)
    }
  }

  private fun biometricKeyExists(@NonNull result: MethodChannel.Result) {
    try {
      val biometricKeyExists = doesBiometricKeyExist()
      result.success(biometricKeyExists)
    } catch (e: Exception) {
      result.error(
        "AUTHFAILED",
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

    val biometricManager = BiometricManager.from(activity)
    val canAuthenticate = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

    if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
      result.success(processBiometricString(
        BiometricManager.from(activity)
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
        else -> "Error checking biometrics"
      }
      result.success("none, $errorString")
    }
  }


  private fun doesBiometricKeyExist(): Boolean {
    return try {
      val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
      keyStore.load(null)
      keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)
    } catch (e: Exception) {
      false
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

  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }
}
