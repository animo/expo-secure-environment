package id.animo.secure.environment

import android.os.Build
import androidx.annotation.RequiresApi
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ExpoSecureEnvironmentModule : Module() {
    @RequiresApi(Build.VERSION_CODES.R)
    override fun definition() = ModuleDefinition {
        Name("ExpoSecureEnvironment")

        Function("generateKeypair") { id: String, biometricsBacked: Boolean ->
            SecureEnvironment.generateKeypair(appContext, id, biometricsBacked)
        }

        Function("getPublicBytesForKeyId") { keyId: String ->
            return@Function SecureEnvironment.getPublicBytesForKeyId(appContext, keyId)
        }

        AsyncFunction("sign") { id: String, message: ByteArray, biometricsBacked: Boolean, promise: Promise ->
            SecureEnvironment.sign(appContext, id, message, biometricsBacked, promise)
        }
    }
}
