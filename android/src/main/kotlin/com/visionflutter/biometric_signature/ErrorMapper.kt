package com.visionflutter.biometric_signature

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.biometric.BiometricManager
import kotlinx.coroutines.CancellationException

object ErrorMapper {
    fun safeErrorMessage(e: Throwable): String {
        return when (val code = mapToBiometricError(e)) {
            BiometricError.USER_CANCELED -> "Authentication was canceled"
            BiometricError.SYSTEM_CANCELED -> "Authentication was canceled by the system"
            BiometricError.NOT_AVAILABLE -> "Biometric authentication is not available"
            BiometricError.NOT_ENROLLED -> "No biometrics enrolled on this device"
            BiometricError.LOCKED_OUT -> "Too many attempts. Try again later"
            BiometricError.LOCKED_OUT_PERMANENT -> "Biometric authentication is permanently locked. Use device credentials to unlock"
            BiometricError.KEY_NOT_FOUND -> "Biometric key not found"
            BiometricError.KEY_INVALIDATED -> "Biometric key has been invalidated"
            BiometricError.SECURITY_UPDATE_REQUIRED -> "A security update is required"
            BiometricError.NOT_SUPPORTED -> "Operation not supported on this device"
            BiometricError.INVALID_INPUT -> "Invalid input provided"
            BiometricError.PROMPT_ERROR -> "Biometric prompt error"
            BiometricError.KEY_ALREADY_EXISTS -> "Key already exists"
            BiometricError.FALLBACK_SELECTED -> "Fallback option selected"
            BiometricError.PASSCODE_NOT_SET -> "No screen lock configured. Set up a PIN, pattern, or password to use biometrics"
            else -> "Biometric operation failed"
        }
    }

    fun mapToBiometricError(e: Throwable): BiometricError {
        val msg = e.message ?: ""
        val causeCode = e.cause?.message?.toIntOrNull()

        return when {
            msg.contains("BIOMETRIC_ERROR_NONE_ENROLLED") -> BiometricError.NOT_ENROLLED
            msg.contains("BIOMETRIC_ERROR_NO_HARDWARE") -> BiometricError.NOT_AVAILABLE
            msg.contains("BIOMETRIC_ERROR_HW_UNAVAILABLE") -> BiometricError.NOT_AVAILABLE
            msg.contains("BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED") -> BiometricError.SECURITY_UPDATE_REQUIRED
            msg.contains("BIOMETRIC_ERROR_UNSUPPORTED") -> BiometricError.NOT_SUPPORTED

            causeCode == 4 -> BiometricError.SYSTEM_CANCELED
            causeCode == 5 -> BiometricError.USER_CANCELED
            causeCode == 7 -> BiometricError.LOCKED_OUT
            causeCode == 9 -> BiometricError.LOCKED_OUT_PERMANENT
            causeCode == 10 -> BiometricError.USER_CANCELED
            causeCode == 13 -> BiometricError.USER_CANCELED
            causeCode == 14 -> BiometricError.PASSCODE_NOT_SET

            e is KeyPermanentlyInvalidatedException -> BiometricError.KEY_INVALIDATED

            e is CancellationException -> BiometricError.USER_CANCELED

            e is IllegalArgumentException && (msg.contains("Base64") || msg.contains("payload")) -> BiometricError.INVALID_INPUT

            else -> BiometricError.UNKNOWN
        }
    }

    fun biometricErrorName(code: Int) = when (code) {
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "BIOMETRIC_ERROR_NO_HARDWARE"
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "BIOMETRIC_ERROR_HW_UNAVAILABLE"
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "BIOMETRIC_ERROR_NONE_ENROLLED"
        BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED"
        BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> "BIOMETRIC_ERROR_UNSUPPORTED"
        BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> "BIOMETRIC_STATUS_UNKNOWN"
        else -> "UNKNOWN_ERROR"
    }

    fun mapBiometricManagerError(
        canAuthResult: Int,
        requestedStrength: BiometricStrength
    ): Pair<BiometricError, String> {
        return when (canAuthResult) {
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> Pair(BiometricError.NOT_AVAILABLE, "No biometric hardware available")
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> Pair(BiometricError.NOT_AVAILABLE, "Biometric hardware unavailable")
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                val strengthName = if (requestedStrength == BiometricStrength.STRONG) "Class 3 (strong)" else "Class 2+ (weak or strong)"
                Pair(BiometricError.NOT_ENROLLED, "No $strengthName biometrics enrolled.")
            }
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> Pair(BiometricError.SECURITY_UPDATE_REQUIRED, "Security update required")
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> Pair(BiometricError.NOT_SUPPORTED, "Biometric authentication not supported")
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> Pair(BiometricError.UNKNOWN, "Biometric status unknown")
            else -> Pair(BiometricError.UNKNOWN, "Unknown biometric error (code: $canAuthResult)")
        }
    }
}
