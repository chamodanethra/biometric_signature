package com.visionflutter.biometric_signature

import android.security.keystore.KeyProperties
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class KeyDescriptionTest {
    private val api23 = 23
    private val api27 = 27
    private val api28 = 28
    private val api30 = 30
    private val api31 = 31

    private fun level(
        sdkInt: Int,
        platformLevel: Int? = null,
        insideSecureHardware: Boolean = true,
        deviceHasStrongBox: Boolean = false
    ) = keySecurityLevelFor(sdkInt, platformLevel, insideSecureHardware, deviceHasStrongBox)

    @Test
    fun `API 31+ reports the keystore's own security level`() {
        assertEquals(KeySecurityLevel.STRONG_BOX, level(api31, KeyProperties.SECURITY_LEVEL_STRONGBOX))
        assertEquals(
            KeySecurityLevel.TRUSTED_ENVIRONMENT,
            level(api31, KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, deviceHasStrongBox = true)
        )
        assertEquals(KeySecurityLevel.SOFTWARE, level(api31, KeyProperties.SECURITY_LEVEL_SOFTWARE))
        assertEquals(KeySecurityLevel.SECURE_HARDWARE, level(api31, KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE))
    }

    @Test
    fun `API 31+ reports null for an unknown or missing level`() {
        assertNull(level(api31, KeyProperties.SECURITY_LEVEL_UNKNOWN))
        assertNull(level(api31, null))
    }

    @Test
    fun `before API 31 a key outside secure hardware is software`() {
        assertEquals(KeySecurityLevel.SOFTWARE, level(api30, insideSecureHardware = false, deviceHasStrongBox = true))
        assertEquals(KeySecurityLevel.SOFTWARE, level(api23, insideSecureHardware = false))
    }

    @Test
    fun `API 28 to 30 can't tell StrongBox from the TEE on StrongBox devices`() {
        assertEquals(KeySecurityLevel.SECURE_HARDWARE, level(api28, deviceHasStrongBox = true))
        assertEquals(KeySecurityLevel.SECURE_HARDWARE, level(api30, deviceHasStrongBox = true))
    }

    @Test
    fun `secure hardware without StrongBox is the TEE`() {
        assertEquals(KeySecurityLevel.TRUSTED_ENVIRONMENT, level(api30))
        assertEquals(KeySecurityLevel.TRUSTED_ENVIRONMENT, level(api23))
        // StrongBox needs API 28, so the feature flag can't matter before it.
        assertEquals(KeySecurityLevel.TRUSTED_ENVIRONMENT, level(api27, deviceHasStrongBox = true))
    }

    @Test
    fun `a key without user authentication has no enrollment or credential policy`() {
        val description = keyPolicyFor(
            KeySecurityLevel.TRUSTED_ENVIRONMENT,
            userAuthenticationRequired = false,
            invalidatedByBiometricEnrollment = true,
            userAuthenticationType = KeyProperties.AUTH_DEVICE_CREDENTIAL
        )
        assertEquals(KeyDescription(KeySecurityLevel.TRUSTED_ENVIRONMENT, false, null, null), description)
    }

    @Test
    fun `the auth type decides whether device credentials unlock the key`() {
        val biometricOnly = keyPolicyFor(
            null, true, false, KeyProperties.AUTH_BIOMETRIC_STRONG
        )
        assertEquals(KeyDescription(null, true, false, false), biometricOnly)

        val withCredential = keyPolicyFor(
            null, true, true,
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        )
        assertEquals(KeyDescription(null, true, true, true), withCredential)
    }

    @Test
    fun `before API 30 device credentials never unlock the key`() {
        assertEquals(false, keyPolicyFor(null, true, true, null).allowsDeviceCredentials)
    }

    @Test
    fun `API 23 auth-bound keys are always invalidated by enrollment`() {
        assertEquals(true, keyPolicyFor(null, true, null, null).invalidatedByBiometricEnrollment)
    }

    @Test
    fun `aliases list the default key first and skip keys the plugin doesn't sign with`() {
        val aliases = userAliasesFrom(
            listOf(
                "biometric_key_payment",
                "biometric_master_key_payment",
                "biometric_master_key",
                "some_other_library_key",
                "biometric_key",
                "biometric_key_auth"
            )
        )
        assertEquals(listOf(null, "auth", "payment"), aliases)
    }

    @Test
    fun `aliases without a default key contain no null`() {
        assertEquals(listOf("a"), userAliasesFrom(listOf("biometric_key_a")))
        assertEquals(emptyList<String?>(), userAliasesFrom(emptyList()))
    }
}
