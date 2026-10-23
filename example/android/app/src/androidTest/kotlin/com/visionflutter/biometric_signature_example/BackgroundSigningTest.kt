package com.visionflutter.biometric_signature_example

import android.app.Activity
import android.util.Base64
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.visionflutter.biometric_signature.BiometricError
import com.visionflutter.biometric_signature.BiometricSignaturePlugin
import com.visionflutter.biometric_signature.CreateKeysConfig
import com.visionflutter.biometric_signature.DecryptResult
import com.visionflutter.biometric_signature.KeyCreationResult
import com.visionflutter.biometric_signature.KeyFormat
import com.visionflutter.biometric_signature.PayloadFormat
import com.visionflutter.biometric_signature.SignatureFormat
import com.visionflutter.biometric_signature.SignatureResult
import com.visionflutter.biometric_signature.SignatureType
import io.flutter.embedding.android.ExclusiveAppComponent
import io.flutter.embedding.engine.FlutterEngine
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Signing and decrypting with a key that needs no user authentication from an
 * engine with no activity attached, as a background engine is (for example one
 * handling a notification action while the app is closed).
 */
@RunWith(AndroidJUnit4::class)
class BackgroundSigningTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val engines = mutableListOf<FlutterEngine>()

    @After
    fun tearDown() {
        engines.firstOrNull()?.let { engine ->
            await<Boolean> { done -> plugin(engine).deleteKeys(ALIAS) { done(it.getOrThrow()) } }
        }
        instrumentation.runOnMainSync { engines.forEach { it.destroy() } }
    }

    @Test
    fun signsWithAKeyThatNeedsNoAuthenticationFromAnEngineWithNoActivity() {
        val created = createKeyOnScreen(
            CreateKeysConfig(
                signatureType = SignatureType.ECDSA,
                requireAuthentication = false,
            )
        )

        // A second engine, never attached to an activity, signs with it.
        val background = newEngine()
        val payload = "payload".toByteArray()
        val signed = await<SignatureResult> { done ->
            plugin(background).createSignatureFromBytes(
                payload,
                ALIAS,
                null,
                SignatureFormat.BASE64,
                KeyFormat.BASE64,
                null,
            ) { done(it.getOrThrow()) }
        }
        assertEquals(signed.error, BiometricError.SUCCESS, signed.code)
        val publicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(created.publicKeyBytes!!))
        val verified = Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(payload)
            verify(signed.signatureBytes!!)
        }
        assertTrue("Signature does not verify against the created key", verified)
    }

    @Test
    fun decryptsWithAnRsaKeyThatNeedsNoAuthenticationFromAnEngineWithNoActivity() {
        val created = createKeyOnScreen(
            CreateKeysConfig(
                signatureType = SignatureType.RSA,
                requireAuthentication = false,
                enableDecryption = true,
            )
        )

        // Encrypted as the README tells servers to for Android RSA keys:
        // RSA-OAEP with SHA-256 and MGF1 SHA-1.
        val plaintext = "background secret"
        val publicKey = KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(created.publicKeyBytes!!))
        val ciphertext = Cipher.getInstance("RSA/ECB/OAEPPadding").run {
            init(
                Cipher.ENCRYPT_MODE,
                publicKey,
                OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT),
            )
            doFinal(plaintext.toByteArray())
        }

        // A second engine, never attached to an activity, decrypts it.
        val background = newEngine()
        val decrypted = await<DecryptResult> { done ->
            plugin(background).decrypt(
                Base64.encodeToString(ciphertext, Base64.NO_WRAP),
                ALIAS,
                PayloadFormat.BASE64,
                null,
                null,
            ) { done(it.getOrThrow()) }
        }
        assertEquals(decrypted.error, BiometricError.SUCCESS, decrypted.code)
        assertEquals(plaintext, decrypted.decryptedData)
    }

    /**
     * Creates a key under [ALIAS] on screen, with an activity attached, as an
     * app creates it, then detaches the activity again.
     */
    private fun createKeyOnScreen(config: CreateKeysConfig): KeyCreationResult =
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            val foreground = newEngine()
            scenario.onActivity { activity -> attach(foreground, activity) }
            val created = await<KeyCreationResult> { done ->
                plugin(foreground).createKeys(ALIAS, config, KeyFormat.BASE64, null) {
                    done(it.getOrThrow())
                }
            }
            instrumentation.runOnMainSync { foreground.activityControlSurface.detachFromActivity() }
            assertNotNull(created.error, created.publicKeyBytes)
            created
        }

    /** A new engine, with the app's plugins registered and no Dart running. */
    private fun newEngine(): FlutterEngine {
        lateinit var engine: FlutterEngine
        instrumentation.runOnMainSync { engine = FlutterEngine(instrumentation.targetContext) }
        engines += engine
        return engine
    }

    private fun attach(engine: FlutterEngine, activity: MainActivity) {
        engine.activityControlSurface.attachToActivity(
            object : ExclusiveAppComponent<Activity> {
                override fun detachFromFlutterEngine() {}

                override fun getAppComponent(): Activity = activity
            },
            activity.lifecycle,
        )
    }

    private fun plugin(engine: FlutterEngine): BiometricSignaturePlugin =
        engine.plugins.get(BiometricSignaturePlugin::class.java) as BiometricSignaturePlugin

    /** Runs [call] on the main thread and waits for the answer it passes on. */
    private fun <T> await(call: (done: (T) -> Unit) -> Unit): T {
        val latch = CountDownLatch(1)
        val answer = AtomicReference<T>()
        instrumentation.runOnMainSync {
            call { result ->
                answer.set(result)
                latch.countDown()
            }
        }
        check(latch.await(30, TimeUnit.SECONDS)) { "No answer within 30 seconds" }
        return answer.get()
    }

    private companion object {
        const val ALIAS = "background_signing_test"
    }
}
