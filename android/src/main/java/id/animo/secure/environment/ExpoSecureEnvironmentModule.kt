package id.animo.secure.environment

import android.annotation.SuppressLint
import android.os.Build
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ExpoSecureEnvironmentModule : Module() {
    // The secure environment needs Android 11, for the user authentication types of keys. Apps can still support older
    // versions: there the checks return false and the other functions throw
    private fun isAndroidVersionSupported() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

    private inline fun <T> requireSupportedAndroidVersion(block: () -> T): T {
        if (!isAndroidVersionSupported()) {
            throw SecureEnvironmentNotSupportedException("The secure environment requires Android 11 (API 30) or newer")
        }
        return block()
    }

    // Every call to SecureEnvironment, which requires Android 11, is behind one of the checks above
    @SuppressLint("NewApi")
    override fun definition() =
        ModuleDefinition {
            Name("ExpoSecureEnvironment")

            Function("isSecureEnvironmentSupported") { keyStorage: KeyStorage ->
                return@Function isAndroidVersionSupported() && SecureEnvironment.isSecureEnvironmentSupported(appContext, keyStorage)
            }

            Function("generateKeypair") { keyId: String, options: GenerateKeypairOptions ->
                requireSupportedAndroidVersion { SecureEnvironment.generateKeypair(appContext, keyId, options) }
            }

            Function("isUserAuthenticationAvailable") { methods: List<UserAuthenticationMethod> ->
                return@Function isAndroidVersionSupported() && SecureEnvironment.isUserAuthenticationAvailable(appContext, methods)
            }

            Function("getKeyStorage") { keyId: String ->
                return@Function requireSupportedAndroidVersion { SecureEnvironment.getKeyStorage(keyId) }
            }

            Function("getAttestationCertificateChain") { keyId: String ->
                return@Function requireSupportedAndroidVersion { SecureEnvironment.getAttestationCertificateChain(keyId) }
            }

            Function("getPublicBytesForKeyId") { keyId: String ->
                return@Function requireSupportedAndroidVersion { SecureEnvironment.getPublicBytesForKeyId(keyId) }
            }

            // The session doesn't change how Android signs, the keystore decides whether the key is unlocked
            AsyncFunction("sign") {
                keyId: String,
                message: ByteArray,
                prompt: AuthenticationPrompt,
                _: UserAuthenticationSession?,
                promise: Promise,
                ->
                requireSupportedAndroidVersion { SecureEnvironment.sign(appContext, keyId, message, prompt, promise) }
            }

            Function("createUserAuthenticationSession") { _: AuthenticationPrompt ->
                return@Function requireSupportedAndroidVersion { UserAuthenticationSession(appContext) }
            }

            // Created by `createUserAuthenticationSession`, JavaScript releases it when the authentication ends. Expo
            // requires a constructor on Android, an empty session is harmless as it holds nothing here
            Class(UserAuthenticationSession::class) {
                Constructor { -> UserAuthenticationSession(appContext) }
            }

            Function("deleteKey") { keyId: String ->
                return@Function requireSupportedAndroidVersion { SecureEnvironment.deleteKey(keyId) }
            }
        }
}
