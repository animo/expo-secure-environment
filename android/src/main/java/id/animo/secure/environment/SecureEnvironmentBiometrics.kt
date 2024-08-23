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
    private val errorCb: (code: Number, message: String) -> Unit,
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
        } ?: errorCb(2323, "No CryptoObjectFound")
    }

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        super.onAuthenticationError(errorCode, errString)
        errorCb(errorCode, errString.toString())
    }

    private fun authenticateWithPrompt(signature: Signature) {
        val prompt = BiometricPrompt(activity, this)
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
    }
    
    fun authenticate(signature: Signature) {
        if (Thread.currentThread() != Looper.getMainLooper().thread) {
            activity.runOnUiThread { this@SecureEnvironmentBiometrics.authenticate(signature) }
            return
        }

        authenticateWithPrompt(signature)
    }
}