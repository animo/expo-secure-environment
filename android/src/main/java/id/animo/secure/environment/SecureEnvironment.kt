package id.animo.secure.environment

import android.content.Context
import android.content.pm.FeatureInfo
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import expo.modules.kotlin.AppContext
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.exception.Exceptions
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

class SecureEnvironment {
    companion object {
        private val Any.TAG: String
            get() {
                val tag = javaClass.simpleName
                return if (tag.length <= 23) tag else tag.substring(0, 23)
            }

        private const val HW_KEYSTORE = "android.hardware.hardware_keystore"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SHA256_WITH_ECDSA_ALGO = "SHA256withECDSA"

        private fun assertHardwareKeystore(context: AppContext) {
            val hasHardwareKeystore =
                context.reactContext?.packageManager?.hasSystemFeature(HW_KEYSTORE) ?: false

            if (!hasHardwareKeystore) {
                throw SecureEnvironmentExceptions.NoHardwareKeyStore()
            }
        }

        private fun assertKeyDoesNotExist(
            context: AppContext,
            keyId: String,
        ) {
            assertHardwareKeystore(context)
            val ks =
                KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(null)
                }

            if (ks.containsAlias(keyId)) {
                throw SecureEnvironmentExceptions.KeyAlreadyExists(keyId)
            }
        }

        private fun assertHasKey(
            context: AppContext,
            keyId: String,
        ) {
            assertHardwareKeystore(context)
            val ks =
                KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(null)
                }

            if (!ks.containsAlias(keyId)) {
                throw SecureEnvironmentExceptions.KeyNotFound(keyId)
            }
        }

        private fun getKeypair(
            context: AppContext,
            keyId: String,
        ): Pair<PrivateKey, PublicKey> {
            assertHardwareKeystore(context)

            val ks =
                KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(null)
                }

            try {
                assertHasKey(context, keyId)
                val privateKey = (ks.getEntry(keyId, null) as KeyStore.PrivateKeyEntry)

                return Pair(privateKey.privateKey, privateKey.certificate.publicKey)
            } catch (e: Exception) {
                throw SecureEnvironmentExceptions.KeyNotFound(keyId)
            }
        }

        // Based on: https://github.com/openwallet-foundation-labs/identity-credential/blob/44de4ea025e6a897180fa687a18d9f3e07af335b/identity-android/src/main/java/com/android/identity/android/securearea/AndroidKeystoreSecureArea.kt#L750z
        @RequiresApi(Build.VERSION_CODES.P)
        private fun getFeatureVersionKeystore(appContext: Context): Int {
            val feature = PackageManager.FEATURE_STRONGBOX_KEYSTORE
            val pm = appContext.packageManager
            if (pm.hasSystemFeature(feature)) {
                var info: FeatureInfo? = null
                val infos = pm.systemAvailableFeatures
                for (n in infos.indices) {
                    val i = infos[n]
                    if (i.name == feature) {
                        info = i
                        break
                    }
                }
                var version = 0
                if (info != null) {
                    version = info.version
                }
                // It's entirely possible that the feature exists but the version number hasn't
                // been set. In that case, assume it's at least KeyMaster 4.1.
                if (version < 41) {
                    version = 41
                }
                return version
            }
            return 0
        }

        @RequiresApi(Build.VERSION_CODES.P)
        fun supportsSecureEnvironment(context: AppContext): Boolean {
            val featureVersionKeystore = getFeatureVersionKeystore(context.reactContext ?: throw Exceptions.ReactContextLost())

            // based on: https://github.com/openwallet-foundation-labs/identity-credential/blob/4c31c5b6fadbe1561b530d28523c60f1427f826c/identity-android/src/main/java/com/android/identity/android/securearea/AndroidKeystoreSecureArea.kt#L169
            return featureVersionKeystore >= 100
        }

        @RequiresApi(Build.VERSION_CODES.R)
        fun generateKeypair(
            context: AppContext,
            keyId: String,
            biometricsBacked: Boolean,
        ) {
            assertHardwareKeystore(context)
            assertKeyDoesNotExist(context, keyId)

            var keyGenParametersBuilder =
                KeyGenParameterSpec
                    .Builder(keyId, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setKeySize(256)
                    .setIsStrongBoxBacked(true)

            if (biometricsBacked) {
                keyGenParametersBuilder =
                    keyGenParametersBuilder
                        .setUserAuthenticationRequired(true)
                        .setInvalidatedByBiometricEnrollment(true)
                        .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }

            val keyGenParameters = keyGenParametersBuilder.build()

            try {
                KeyPairGenerator.getInstance("EC", ANDROID_KEYSTORE).apply {
                    initialize(keyGenParameters)
                    generateKeyPair()
                }
            } catch (e: Exception) {
                throw SecureEnvironmentExceptions.CouldNotGenerateKeyPair()
            }
        }

        // Return public bytes in DER-encoded (SubjectPublicKeyInfo) format
        fun getPublicBytesForKeyId(
            context: AppContext,
            keyId: String,
        ): ByteArray = getKeypair(context, keyId).second.encoded

        // Return a signature over the message in DER-encoded (ECDA-sig-Value: r,s) format
        fun sign(
            context: AppContext,
            keyId: String,
            message: ByteArray,
            biometricsBacked: Boolean,
            promise: Promise,
        ) {
            val privateKey = getKeypair(context, keyId).first

            val signature =
                Signature.getInstance(SHA256_WITH_ECDSA_ALGO).apply {
                    initSign(privateKey)
                }

            try {
                if (biometricsBacked) {
                    SecureEnvironmentBiometrics(
                        context,
                        { sig: ByteArray -> promise.resolve(sig) },
                        { code: Number, msg: String -> promise.reject(CodedException("code: $code, msg: $msg")) },
                        message,
                    ).authenticate(signature)
                } else {
                    signature.update(message)
                    promise.resolve(signature.sign())
                }
            } catch (e: Exception) {
                promise.reject(CodedException(e))
            }
        }

        // Delete the key from the secure environment
        fun deleteKey(
            context: AppContext,
            keyId: String,
        ) {
            assertHardwareKeystore(context)
            assertHasKey(context, keyId)

            val ks =
                KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(null)
                }

            ks.deleteEntry(keyId)
        }
    }
}
