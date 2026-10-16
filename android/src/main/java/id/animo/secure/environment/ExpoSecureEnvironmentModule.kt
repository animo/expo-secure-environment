package id.animo.secure.environment

import android.os.Build
import androidx.annotation.RequiresApi
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ExpoSecureEnvironmentModule : Module() {
    @RequiresApi(Build.VERSION_CODES.R)
    override fun definition() =
        ModuleDefinition {
            Name("ExpoSecureEnvironment")

            Function("isSecureEnvironmentSupported") { keyStorage: KeyStorage ->
                return@Function SecureEnvironment.isSecureEnvironmentSupported(appContext, keyStorage)
            }

            Function("generateKeypair") { keyId: String, options: GenerateKeypairOptions ->
                SecureEnvironment.generateKeypair(appContext, keyId, options)
            }

            Function("isUserAuthenticationAvailable") { methods: List<UserAuthenticationMethod> ->
                return@Function SecureEnvironment.isUserAuthenticationAvailable(appContext, methods)
            }

            Function("getKeyStorage") { keyId: String ->
                return@Function SecureEnvironment.getKeyStorage(keyId)
            }

            Function("getAttestationCertificateChain") { keyId: String ->
                return@Function SecureEnvironment.getAttestationCertificateChain(keyId)
            }

            Function("getPublicBytesForKeyId") { keyId: String ->
                return@Function SecureEnvironment.getPublicBytesForKeyId(keyId)
            }

            // The session doesn't change how Android signs, the keystore decides whether the key is unlocked
            AsyncFunction("sign") {
                keyId: String,
                message: ByteArray,
                prompt: AuthenticationPrompt,
                _: UserAuthenticationSession?,
                promise: Promise,
                ->
                SecureEnvironment.sign(appContext, keyId, message, prompt, promise)
            }

            AsyncFunction("authenticate") { methods: List<UserAuthenticationMethod>, prompt: AuthenticationPrompt, promise: Promise ->
                SecureEnvironment.authenticate(appContext, methods, prompt, promise)
            }

            // Created by `authenticate`, JavaScript releases it when the authentication ends. Expo requires a
            // constructor on Android, an empty session is harmless as it holds nothing here
            Class(UserAuthenticationSession::class) {
                Constructor { -> UserAuthenticationSession(appContext) }
            }

            Function("deleteKey") { keyId: String ->
                return@Function SecureEnvironment.deleteKey(keyId)
            }
        }
}
