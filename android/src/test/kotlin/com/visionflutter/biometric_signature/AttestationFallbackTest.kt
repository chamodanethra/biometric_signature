package com.visionflutter.biometric_signature

import java.security.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test

class AttestationFallbackTest {
    private val key = KeyPair(null, null)
    private val unsupported = KeyAttestationException("cannot attest")
    private val transient = KeyAttestationException("not provisioned", isTransient = true)
    private val strongBoxFailure = IllegalStateException("StrongBox unavailable")

    private val attempts = mutableListOf<Boolean>()
    private var cleanUps = 0

    private fun attempt(failStrongBox: Boolean = false, failTee: Boolean = false) = { useStrongBox: Boolean ->
        attempts += useStrongBox
        if (useStrongBox && failStrongBox) throw strongBoxFailure
        if (!useStrongBox && failTee) throw IllegalStateException("TEE failed")
        key
    }

    private fun fallback(
        mode: AttestationMode,
        attestationFailure: KeyAttestationException,
        strongBoxBacked: Boolean = true,
        generateUnattested: (Boolean) -> KeyPair = attempt()
    ) = generateWithAttestationFallback(
        mode,
        { throw attestationFailure },
        strongBoxBacked,
        generateUnattested,
        { cleanUps++ }
    )

    @Test
    fun `StrongBox success needs no retry`() {
        assertSame(key, generateWithTeeRetry(true, attempt(), { cleanUps++ }))
        assertEquals(listOf(true), attempts)
        assertEquals(0, cleanUps)
    }

    @Test
    fun `failed StrongBox attempt retries in the TEE`() {
        assertSame(key, generateWithTeeRetry(true, attempt(failStrongBox = true), { cleanUps++ }))
        assertEquals(listOf(true, false), attempts)
        assertEquals(1, cleanUps)
    }

    @Test
    fun `no TEE retry when StrongBox was never requested`() {
        val thrown = assertThrows(IllegalStateException::class.java) {
            generateWithTeeRetry(false, attempt(failStrongBox = true), { cleanUps++ })
        }
        assertSame(strongBoxFailure, thrown)
        assertEquals(listOf(true), attempts)
        assertEquals(1, cleanUps)
    }

    @Test
    fun `the TEE failure is rethrown when both attempts fail`() {
        val thrown = assertThrows(IllegalStateException::class.java) {
            generateWithTeeRetry(true, attempt(failStrongBox = true, failTee = true), { cleanUps++ })
        }
        assertEquals("TEE failed", thrown.message)
        assertEquals(2, cleanUps)
    }

    @Test
    fun `unattested fallback retries in the TEE after StrongBox fails`() {
        val result = fallback(
            AttestationMode.PREFERRED,
            unsupported,
            generateUnattested = attempt(failStrongBox = true)
        )

        assertSame(key, result.keyPair)
        assertNull(result.attestationCertChain)
        assertSame(unsupported, result.attestationFailure)
        assertEquals(listOf(true, false), attempts)
        assertEquals(1, cleanUps)
    }

    @Test
    fun `enforceOnChallenge never falls back`() {
        assertSame(unsupported, assertThrows(KeyAttestationException::class.java) {
            fallback(AttestationMode.ENFORCE_ON_CHALLENGE, unsupported)
        })
        assertEquals(emptyList<Boolean>(), attempts)
    }

    @Test
    fun `enforceOnChallengeIfSupported falls back only when unsupported`() {
        assertSame(unsupported, fallback(AttestationMode.ENFORCE_ON_CHALLENGE_IF_SUPPORTED, unsupported).attestationFailure)
        assertSame(transient, assertThrows(KeyAttestationException::class.java) {
            fallback(AttestationMode.ENFORCE_ON_CHALLENGE_IF_SUPPORTED, transient)
        })
    }

    @Test
    fun `preferred falls back on transient failures`() {
        val result = fallback(AttestationMode.PREFERRED, transient)
        assertSame(transient, result.attestationFailure)
        assertEquals(BiometricError.NOT_AVAILABLE, result.attestationFailure?.errorCode)
    }

    @Test
    fun `an attested key is returned as-is`() {
        val attested = GeneratedKey(key, listOf(byteArrayOf(1)))
        val result = generateWithAttestationFallback(
            AttestationMode.PREFERRED, { attested }, true, attempt(), { cleanUps++ }
        )
        assertSame(attested, result)
        assertEquals(emptyList<Boolean>(), attempts)
    }
}
