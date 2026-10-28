package id.animo.secure.environment

import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.PromptInfo
import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.AppContext
import expo.modules.kotlin.exception.CodedException
import java.security.Signature

/**
 * Shows the system prompt where the user authenticates with the `authenticators`.
 *
 * Prompts are shown one at a time, in the order they are requested. androidx gives the result of a prompt to the
 * callback of the latest prompt of the activity, so a second prompt at the same time would take the result of the first.
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
        // The prompt has to be shown from the main thread
        mainHandler.post {
            waiting.addLast { show(signature, onSuccess, onError) }
            if (!isShowing) showNext()
        }
    }

    // Runs on the main thread, and calls `finish` once the prompt has a result or can't be shown
    private fun show(
        signature: Signature?,
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
        onError: (CodedException) -> Unit,
    ) {
        val fail = { error: CodedException ->
            finish()
            onError(error)
        }

        val activity =
            appContext.currentActivity as? FragmentActivity
                ?: return fail(UserAuthenticationFailedException("No activity to show the authentication prompt"))

        // androidx doesn't show the prompt and never calls back when the app is in the background
        if (activity.supportFragmentManager.isStateSaved) {
            return fail(UserAuthenticationCanceledException("The app is in the background, so the authentication prompt can't be shown"))
        }

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
                    finish()
                    onSuccess(result)
                }

                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence,
                ) {
                    fail(toException(errorCode, errString.toString()))
                }
            }

        try {
            val biometricPrompt = BiometricPrompt(activity, callback)
            if (signature != null) {
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
            } else {
                biometricPrompt.authenticate(promptInfo)
            }
        } catch (e: Exception) {
            fail(e as? CodedException ?: CodedException(e))
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

    companion object {
        private val mainHandler = Handler(Looper.getMainLooper())

        // Only used on the main thread
        private val waiting = ArrayDeque<() -> Unit>()
        private var isShowing = false

        private fun showNext() {
            val show = waiting.removeFirstOrNull() ?: return
            isShowing = true
            show()
        }

        // androidx calls back before it removes the prompt, so the next prompt is shown after that
        private fun finish() {
            mainHandler.post {
                isShowing = false
                showNext()
            }
        }
    }
}
