package id.animo.secure.environment

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import expo.modules.kotlin.AppContext
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
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

        private fun getKeypair(context: AppContext, keyId: String): Pair<PrivateKey, PublicKey> {
            assertHardwareKeystore(context)

            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                load(null)
            }

            try {
                val privateKey = (ks.getEntry(keyId, null) as KeyStore.PrivateKeyEntry)

                return Pair(privateKey.privateKey, privateKey.certificate.publicKey)
            } catch (e: Exception) {
                Log.e(TAG, "Error occurred while fetching a keypair: ${e.message}")
                throw SecureEnvironmentExceptions.NoKeyWithIdFound(keyId)
            }
        }

        @RequiresApi(Build.VERSION_CODES.R)
        fun generateKeypair(context: AppContext, keyId: String, biometricsBacked: Boolean) {
            assertHardwareKeystore(context)

            var keyGenParametersBuilder =
                KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setKeySize(256)
                    .setIsStrongBoxBacked(true)

            if (biometricsBacked) {
                keyGenParametersBuilder =
                    keyGenParametersBuilder.setUserAuthenticationRequired(true)
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
                Log.e(TAG, "Error occurred while generating a keypair: ${e.message}")
                throw SecureEnvironmentExceptions.CouldNotGenerateKeyPair()
            }
        }

        // Return public bytes in DER-encoded (SubjectPublicKeyInfo) format
        fun getPublicBytesForKeyId(context: AppContext, keyId: String): ByteArray =
            getKeypair(context, keyId).second.encoded

        // Return a signature over the message in DER-encoded (ECDA-sig-Value: r,s) format
        fun sign(
            context: AppContext,
            keyId: String,
            message: ByteArray,
            biometricsBacked: Boolean,
            promise: Promise
        ) {
            val privateKey = getKeypair(context, keyId).first

            val signature = Signature.getInstance(SHA256_WITH_ECDSA_ALGO).apply {
                initSign(privateKey)
            }

            try {
                if (biometricsBacked) {
                    SecureEnvironmentBiometrics(
                        context,
                        { sig: ByteArray -> promise.resolve(sig) },
                        message
                    ).authenticate(signature)
                } else {
                    signature.update(message)
                    promise.resolve(signature.sign())
                }
            } catch (e: Exception) {
                promise.reject(CodedException(e))
            }
        }
    }
}
