package id.animo.secure.environment

import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.PromptInfo
import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.AppContext
import java.security.Signature

class SecureEnvironmentBiometrics(
    private val appContext: AppContext,
    private val signedCb: (sig: ByteArray) -> Unit,
    private val toBeSigned: ByteArray,
    private val activity: FragmentActivity = appContext.currentActivity as FragmentActivity,
    private val promptInfo: PromptInfo = PromptInfo.Builder()
        .setTitle("Biometrics")
        .setSubtitle("Authenticate to sign data")
        .setNegativeButtonText("Cancel")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG).build(),

    ) : BiometricPrompt.AuthenticationCallback() {
    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        result.cryptoObject?.signature?.let { sig ->
            sig.update(toBeSigned)
            val signature = sig.sign()
            signedCb(signature)
        } ?: throw SecureEnvironmentExceptions.NoSignatureOnCryptoObject()
    }

    private fun authenticateWithPrompt(signature: Signature) {
        val prompt = BiometricPrompt(activity, this)
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
    }

    private fun waitResult() {
        if (Thread.currentThread() === Looper.getMainLooper().thread) {
            throw SecureEnvironmentExceptions.NotExecutedFromMainThread()
        }

        try {
            synchronized(this) { (this as Object).wait() }
        } catch (ignored: InterruptedException) {
            /* shutdown sequence */
        }
    }

    fun authenticate(signature: Signature) {
        if (Thread.currentThread() != Looper.getMainLooper().thread) {
            activity.runOnUiThread { this@SecureEnvironmentBiometrics.authenticate(signature) }
            waitResult()
            return
        }

        authenticateWithPrompt(signature)
    }
}