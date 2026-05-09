package com.visionflutter.biometric_signature

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Resources
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/// Result of a biometric authentication attempt.
///
/// Currently only [Success] is produced — failures are surfaced via thrown
/// exceptions. Modelled as a sealed interface to keep the contract open for
/// future variants (e.g. canceled, retry-needed) without breaking callers.
sealed interface AuthenticationOutcome {
    data class Success(
        val cryptoObject: BiometricPrompt.CryptoObject?,
        val authenticationType: AuthenticationType
    ) : AuthenticationOutcome
}

class BiometricPromptHelper(private val appContext: Context) {

    fun detectBiometricTypes(): List<BiometricType> {
        val pm = appContext.packageManager
        val biometricManager = BiometricManager.from(appContext)
        val canAuth = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS

        if (!canAuth) return emptyList()

        val hasFace = pm.hasSystemFeature(PackageManager.FEATURE_FACE)
        val hasFingerprint = pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        val hasIris = pm.hasSystemFeature(PackageManager.FEATURE_IRIS)
        val featureBackedTypes = mutableListOf<BiometricType>()
        if (hasFace) featureBackedTypes.add(BiometricType.FACE)
        if (hasFingerprint) featureBackedTypes.add(BiometricType.FINGERPRINT)
        if (hasIris) featureBackedTypes.add(BiometricType.IRIS)

        var buttonLabel: String? = null
        try {
            val getStringsMethod = BiometricManager::class.java.getMethod(
                "getStrings", Int::class.javaPrimitiveType
            )
            val strings = getStringsMethod.invoke(
                biometricManager, BiometricManager.Authenticators.BIOMETRIC_STRONG
            )
            if (strings != null) {
                val getButtonLabel = strings.javaClass.getMethod("getButtonLabel")
                val getPromptMessage = try {
                    strings.javaClass.getMethod("getPromptMessage")
                } catch (_: Exception) {
                    null
                }

                buttonLabel = listOfNotNull(
                    (getButtonLabel.invoke(strings) as? CharSequence)?.toString(),
                    (getPromptMessage?.invoke(strings) as? CharSequence)?.toString()
                ).joinToString(" ")
            }
        } catch (_: Exception) {}

        val systemRes = Resources.getSystem()

        val faceTerms = listOfNotNull(
            getFrameworkString(systemRes, "face_icon_content_description"),
            getFrameworkString(systemRes, "biometric_face_icon_description"),
            getFrameworkString(systemRes, "face_sensor_privacy_title"),
            getFrameworkString(systemRes, "face_error_not_recognized"),
            getFrameworkString(systemRes, "face_error_lockout"),
            getFrameworkString(systemRes, "face_error_lockout_permanent"),
            getFrameworkString(systemRes, "face_acquired_too_bright"),
            getFrameworkString(systemRes, "face_authenticated"),
            getFrameworkString(systemRes, "biometric_dialog_use_face"),
            getFrameworkString(systemRes, "face_unlock_recognizing")
        )

        val fingerprintTerms = listOfNotNull(
            getFrameworkString(systemRes, "fingerprint_icon_content_description"),
            getFrameworkString(systemRes, "biometric_fingerprint_icon_description"),
            getFrameworkString(systemRes, "fingerprint_setup_notification_title"),
            getFrameworkString(systemRes, "fingerprint_error_not_match"),
            getFrameworkString(systemRes, "fingerprint_error_lockout"),
            getFrameworkString(systemRes, "fingerprint_error_lockout_permanent"),
            getFrameworkString(systemRes, "fingerprint_authenticated"),
            getFrameworkString(systemRes, "biometric_dialog_use_fingerprint")
        )

        val irisTerms = listOfNotNull(
            getFrameworkString(systemRes, "iris_icon_content_description"),
            getFrameworkString(systemRes, "biometric_iris_icon_description"),
            getFrameworkString(systemRes, "iris_error_not_recognized"),
            getFrameworkString(systemRes, "iris_error_lockout")
        )

        if (buttonLabel.isNullOrBlank()) return featureBackedTypes

        val labelMatchedTypes = mutableListOf<BiometricType>()
        if (hasFace && matchesLabel(buttonLabel, faceTerms)) {
            labelMatchedTypes.add(BiometricType.FACE)
        }

        if (hasFingerprint && matchesLabel(buttonLabel, fingerprintTerms)) {
            labelMatchedTypes.add(BiometricType.FINGERPRINT)
        }

        if (hasIris && matchesLabel(buttonLabel, irisTerms)) {
            labelMatchedTypes.add(BiometricType.IRIS)
        }

        return if (labelMatchedTypes.isNotEmpty()) labelMatchedTypes else featureBackedTypes
    }

    suspend fun checkBiometricAvailability(
        activity: FragmentActivity,
        allowDeviceCredentials: Boolean
    ) {
        val authenticators = getAuthenticators(allowDeviceCredentials)
        val canAuth = BiometricManager.from(activity).canAuthenticate(authenticators)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            throw SecurityException("Biometric not available (code: ${ErrorMapper.biometricErrorName(canAuth)})")
        }
    }

    suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String?,
        description: String?,
        cancelText: String,
        allowDeviceCredentials: Boolean,
        cryptoObject: BiometricPrompt.CryptoObject?
    ): AuthenticationOutcome.Success = suspendCancellableCoroutine { cont ->
        val authenticators = getAuthenticators(allowDeviceCredentials)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (cont.isActive) cont.resume(
                    AuthenticationOutcome.Success(
                        cryptoObject = result.cryptoObject,
                        authenticationType = mapAuthenticationType(result.authenticationType)
                    )
                )
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (cont.isActive) {
                    cont.resumeWithException(
                        SecurityException(
                            "$errString",
                            Throwable(errorCode.toString())
                        )
                    )
                }
            }

            override fun onAuthenticationFailed() { /* Retry */ }
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(authenticators)
            .apply {
                if (!subtitle.isNullOrBlank()) setSubtitle(subtitle)
                if (!description.isNullOrBlank()) setDescription(description)
                if (!(allowDeviceCredentials && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)) {
                    setNegativeButtonText(cancelText)
                }
            }
            .build()

        runCatching {
            activity.setTheme(androidx.appcompat.R.style.Theme_AppCompat_Light_DarkActionBar)
            val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            if (cryptoObject != null) prompt.authenticate(promptInfo, cryptoObject)
            else prompt.authenticate(promptInfo)
        }.onFailure { e -> if (cont.isActive) cont.resumeWithException(e) }
    }

    fun getAuthenticators(
        allowDeviceCredentials: Boolean,
        biometricStrength: BiometricStrength = BiometricStrength.STRONG
    ): Int {
        val biometricAuth = when (biometricStrength) {
            BiometricStrength.STRONG -> BiometricManager.Authenticators.BIOMETRIC_STRONG
            BiometricStrength.WEAK -> BiometricManager.Authenticators.BIOMETRIC_WEAK
        }

        return if (allowDeviceCredentials && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            biometricAuth or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            biometricAuth
        }
    }

    private fun matchesLabel(buttonLabel: String?, terms: List<String>): Boolean {
        if (buttonLabel.isNullOrBlank() || terms.isEmpty()) return false
        return terms.any { term ->
            if (buttonLabel.contains(term, ignoreCase = true)) return@any true

            val hasCJK = term.any { Character.isIdeographic(it.code) }
            if (hasCJK) {
                (0 until term.length - 1).any { i ->
                    val bigram = term.substring(i, i + 2)
                    bigram.any { Character.isIdeographic(it.code) } &&
                            buttonLabel.contains(bigram)
                }
            } else {
                term.split("\\s+".toRegex())
                    .filter { it.length >= 3 }
                    .any { word -> buttonLabel.contains(word, ignoreCase = true) }
            }
        }
    }

    private fun mapAuthenticationType(type: Int): AuthenticationType {
        return when (type) {
            BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC -> AuthenticationType.BIOMETRIC
            BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL -> AuthenticationType.CREDENTIAL
            else -> AuthenticationType.UNKNOWN
        }
    }

    private fun getFrameworkString(res: Resources, name: String): String? {
        return try {
            val id = res.getIdentifier(name, "string", "android")
            if (id != 0) res.getString(id) else null
        } catch (_: Exception) {
            null
        }
    }
}
