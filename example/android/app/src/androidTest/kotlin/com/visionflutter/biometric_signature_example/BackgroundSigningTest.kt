package com.visionflutter.biometric_signature_example

import android.app.Activity
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.visionflutter.biometric_signature.BiometricSignaturePlugin
import com.visionflutter.biometric_signature.CreateKeysConfig
import com.visionflutter.biometric_signature.KeyCreationResult
import com.visionflutter.biometric_signature.KeyFormat
import com.visionflutter.biometric_signature.SignatureFormat
import com.visionflutter.biometric_signature.SignatureResult
import com.visionflutter.biometric_signature.SignatureType
import io.flutter.embedding.android.ExclusiveAppComponent
import io.flutter.embedding.engine.FlutterEngine
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Signing with a key that needs no user authentication from an engine with no
 * activity attached, as a background engine is (for example one handling a
 * notification action while the app is closed).
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
        // The key is created on screen, with an activity attached, as an app
        // creates it.
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            val foreground = newEngine()
            scenario.onActivity { activity -> attach(foreground, activity) }
            val created = await<KeyCreationResult> { done ->
                plugin(foreground).createKeys(
                    ALIAS,
                    CreateKeysConfig(
                        signatureType = SignatureType.ECDSA,
                        requireAuthentication = false,
                    ),
                    KeyFormat.BASE64,
                    null,
                ) { done(it.getOrThrow()) }
            }
            assertNotNull(created.error, created.publicKey)
        }

        // A second engine, never attached to an activity, signs with it.
        val background = newEngine()
        val signed = await<SignatureResult> { done ->
            plugin(background).createSignatureFromBytes(
                "payload".toByteArray(),
                ALIAS,
                null,
                SignatureFormat.BASE64,
                KeyFormat.BASE64,
                null,
            ) { done(it.getOrThrow()) }
        }
        assertNotNull(signed.error, signed.signature)
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
