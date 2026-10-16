package id.animo.secure.environment

import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.PromptInfo
import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.AppContext
import expo.modules.kotlin.exception.CodedException
import java.security.Signature

/**
 * Shows the system prompt where the user authenticates with the `authenticators`.
 */
class UserAuthenticationPrompt(
    private val appContext: AppContext,
    private val prompt: AuthenticationPrompt,
    private val authenticators: Int,
) {
    /**
     * Authenticates the user. Pass a `signature` for keys that require authentication for every use, the user
     * authentication then only unlocks this signature. Without one, it unlocks the keys with a validity duration.
     */
    fun authenticate(
        signature: Signature?,
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
        onError: (CodedException) -> Unit,
    ) {
        val activity =
            appContext.currentActivity as? FragmentActivity
                ?: return onError(UserAuthenticationFailedException("No activity to show the authentication prompt"))

        val promptInfo =
            PromptInfo
                .Builder()
                .setTitle(prompt.title)
                .setSubtitle(prompt.subtitle)
                .setAllowedAuthenticators(authenticators)
                .apply {
                    // With the device credential the prompt has a button to use it instead, it can't have a cancel button
                    if (authenticators and Authenticators.DEVICE_CREDENTIAL == 0) {
                        setNegativeButtonText(prompt.cancel)
                    }
                }.build()

        val callback =
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess(result)
                }

                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence,
                ) {
                    onError(toException(errorCode, errString.toString()))
                }
            }

        // The prompt has to be shown from the main thread
        activity.runOnUiThread {
            val biometricPrompt = BiometricPrompt(activity, callback)
            if (signature != null) {
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
            } else {
                biometricPrompt.authenticate(promptInfo)
            }
        }
    }

    private fun toException(
        errorCode: Int,
        message: String,
    ): CodedException =
        when (errorCode) {
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_CANCELED,
            -> UserAuthenticationCanceledException(message)

            BiometricPrompt.ERROR_NO_BIOMETRICS,
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
            BiometricPrompt.ERROR_HW_NOT_PRESENT,
            BiometricPrompt.ERROR_HW_UNAVAILABLE,
            BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED,
            -> UserAuthenticationUnavailableException(message)

            // Temporary lockouts end after 30 seconds, permanent ones after the user unlocks with the device credential
            BiometricPrompt.ERROR_LOCKOUT,
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
            -> UserAuthenticationLockedOutException(message)

            else -> UserAuthenticationFailedException("$message (error code $errorCode)")
        }
}
