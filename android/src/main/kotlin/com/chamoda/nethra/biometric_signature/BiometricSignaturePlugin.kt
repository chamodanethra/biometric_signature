package com.chamoda.nethra.biometric_signature

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Base64.DEFAULT
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
      "biometricKeysExist" -> {
        biometricKeysExist(result)
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
      var publicKeyString: String =
        Base64.encodeToString(encodedPublicKey, DEFAULT)
      val resultMap = mutableMapOf<String, String>()
      publicKeyString = publicKeyString.replace("\r", "").replace("\n", "")
      resultMap["publicKey"] = publicKeyString
      result.success(resultMap)

    } catch (e: Exception) {
      result.error(
        "AUTHFAILED",
        "Error generating public private keys", null
      )
    }
  }

  private fun createSignature(
    params: MutableMap<String, String>?,
    @NonNull result: MethodChannel.Result
  ) {
    var resultSent = false
    try {
      val cancelButtonText: String = params?.get("cancelButtonText") ?: "Cancel"
      val promptMessage: String = params?.get("promptMessage") ?: "Welcome"
      val payload: String =
        Base64.encodeToString("somewhat secret".toByteArray(Charsets.UTF_8), DEFAULT)
      val signature = Signature.getInstance("SHA256withRSA")
      val keyStore = KeyStore.getInstance("AndroidKeyStore")
      keyStore.load(null)
      val privateKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as PrivateKey
      signature.initSign(privateKey)
      val cryptoObject = BiometricPrompt.CryptoObject(signature)
      val executor = ContextCompat.getMainExecutor(activity)
      val biometricPrompt =
        BiometricPrompt(
          activity, executor,
          object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(
              errorCode: Int,
              errString: CharSequence
            ) {
              super.onAuthenticationError(errorCode, errString)
              if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON /*|| errorCode == BiometricPrompt.ERROR_USER_CANCELED */) {
                result.error("userCancel", "userCancel", null)
              } else if (errorCode == BiometricPrompt.ERROR_USER_CANCELED) {
                result.error("$errorCode", errString.toString(), null)
              }
              resultSent = true
            }

            override fun onAuthenticationSucceeded(
              authResult: BiometricPrompt.AuthenticationResult
            ) {
              super.onAuthenticationSucceeded(authResult)
              val cryptoObject: BiometricPrompt.CryptoObject =
                authResult.cryptoObject!!
              val cryptoSignature = cryptoObject.signature!!
              cryptoSignature.update(payload.toByteArray())
              val signed = cryptoSignature.sign()
              var signedString = Base64.encodeToString(signed, DEFAULT)
              signedString =
                signedString.replace("\r", "").replace("\n", "")
              if (!resultSent) {
                val resultMap = mutableMapOf<String, String>()
                resultMap["signature"] = signedString
                result.success(resultMap)
                resultSent = true
              }
            }
          })

      val promptInfo = PromptInfo.Builder()
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .setNegativeButtonText(cancelButtonText)
        .setTitle(promptMessage)
        .build()
      biometricPrompt.authenticate(promptInfo, cryptoObject)
    } catch (e: Exception) {
      result.error(
        "AUTHFAILED",
        "Error generating signature: " + e.message, null
      )
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
      val resultMap = mutableMapOf<String, String>()
      resultMap["deleted"] = "false"
      result.success(resultMap)
    }
  }

  private fun biometricKeysExist(@NonNull result: MethodChannel.Result) {
    try {
      val resultBoolean = doesBiometricKeyExist()
      result.success(resultBoolean)
    } catch (e: Exception) {
      result.error(
        "AUTHFAILED",
        "Error checking if biometric key exists: ${e.message}", null
      )
    }
  }

  private fun biometricAuthAvailable(@NonNull result: MethodChannel.Result) {
    try {
      val canAuthenticate = BiometricManager.from(activity).canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG
      )
      val resultMap = mutableMapOf<String, String>()
      "fingerprint|face|iris".toRegex().find(
        BiometricManager.from(activity)
          .getStrings(BiometricManager.Authenticators.BIOMETRIC_STRONG)?.buttonLabel.toString()
          .lowercase(
            Locale.ROOT
          )
      )?.value

      if (canAuthenticate === BiometricManager.BIOMETRIC_SUCCESS) {
        resultMap["biometricsType"] =
          "fingerprint|face|iris".toRegex().find(
            BiometricManager.from(activity)
              .getStrings(BiometricManager.Authenticators.BIOMETRIC_STRONG)?.buttonLabel.toString()
              .lowercase(
                Locale.ROOT
              )
          )?.value ?: "biometrics"
      } else {
        when (canAuthenticate) {
          BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> resultMap["error"] =
            "BIOMETRIC_ERROR_NO_HARDWARE"
          BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> resultMap["error"] =
            "BIOMETRIC_ERROR_HW_UNAVAILABLE"
          BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> resultMap["error"] =
            "BIOMETRIC_ERROR_NONE_ENROLLED"
        }
        resultMap["biometricsType"] = "none"
      }
      result.success(resultMap)
    } catch (e: Exception) {
      result.error(
        "AUTHFAILED",
        "Error checking if biometric key exists: ${e.message}", null
      )
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
