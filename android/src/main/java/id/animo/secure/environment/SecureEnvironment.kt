package id.animo.secure.environment

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import expo.modules.kotlin.AppContext
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.exception.Exceptions
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.UUID

@RequiresApi(Build.VERSION_CODES.R)
class SecureEnvironment {
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SHA256_WITH_ECDSA_ALGO = "SHA256withECDSA"

        private fun getKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        private inline fun Promise.rejectOnError(block: () -> Unit) {
            try {
                block()
            } catch (e: Exception) {
                reject(e as? CodedException ?: CodedException(e))
            }
        }

        private fun assertKeyDoesNotExist(keyId: String) {
            if (getKeyStore().containsAlias(keyId)) {
                throw KeyAlreadyExistsException(keyId)
            }
        }

        private fun getPrivateKeyEntry(keyId: String): KeyStore.PrivateKeyEntry =
            getKeyStore().getEntry(keyId, null) as? KeyStore.PrivateKeyEntry ?: throw KeyNotFoundException(keyId)

        private fun getKeyInfo(privateKey: PrivateKey): KeyInfo =
            KeyFactory
                .getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
                .getKeySpec(privateKey, KeyInfo::class.java)

        // Android 11, and newer versions for some keys, only tell whether a key is in secure hardware, not whether
        // that's StrongBox or the TEE
        private const val SECURE_HARDWARE = "secureHardware"

        private fun getKeyStorage(keyInfo: KeyInfo): String {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> return KeyStorage.STRONG_BOX.value
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> return KeyStorage.TRUSTED_ENVIRONMENT.value
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> return KeyStorage.SOFTWARE.value
                }
            }

            @Suppress("DEPRECATION")
            return if (keyInfo.isInsideSecureHardware) SECURE_HARDWARE else KeyStorage.SOFTWARE.value
        }

        private fun isInSecureHardware(keyInfo: KeyInfo): Boolean = getKeyStorage(keyInfo) != KeyStorage.SOFTWARE.value

        private fun toAuthenticators(methods: List<UserAuthenticationMethod>): Int =
            methods.fold(0) { authenticators, method ->
                authenticators or
                    when (method) {
                        UserAuthenticationMethod.BIOMETRIC -> Authenticators.BIOMETRIC_STRONG
                        UserAuthenticationMethod.DEVICE_CREDENTIAL -> Authenticators.DEVICE_CREDENTIAL
                    }
            }

        // Converts the `KeyProperties.AUTH_*` flags of a key to the authenticators of the prompt that unlocks it
        private fun toAuthenticators(keyInfo: KeyInfo): Int {
            var authenticators = 0
            if (keyInfo.userAuthenticationType and KeyProperties.AUTH_BIOMETRIC_STRONG != 0) {
                authenticators = authenticators or Authenticators.BIOMETRIC_STRONG
            }
            if (keyInfo.userAuthenticationType and KeyProperties.AUTH_DEVICE_CREDENTIAL != 0) {
                authenticators = authenticators or Authenticators.DEVICE_CREDENTIAL
            }
            return authenticators
        }

        private fun getUserAuthenticationStatus(
            context: AppContext,
            authenticators: Int,
        ): Int {
            val reactContext = context.reactContext ?: throw Exceptions.ReactContextLost()
            return BiometricManager.from(reactContext).canAuthenticate(authenticators)
        }

        private fun assertUserAuthenticationAvailable(
            context: AppContext,
            authenticators: Int,
        ) {
            val status = getUserAuthenticationStatus(context, authenticators)
            if (status != BiometricManager.BIOMETRIC_SUCCESS) {
                throw UserAuthenticationUnavailableException(
                    "The user can't authenticate with the requested methods (status $status). Make sure biometrics are enrolled or a screen lock is set.",
                )
            }
        }

        // Whether the default key storage, which stores every key that's not in StrongBox, is secure hardware (the
        // TEE) or software. Only a generated key tells: emulators report a hardware keystore, but store keys in software
        @Volatile
        private var defaultKeyStorageIsSecure: Boolean? = null

        private fun isDefaultKeyStorageSecure(): Boolean =
            defaultKeyStorageIsSecure ?: run {
                val keyId = "id.animo.secure.environment.probe.${UUID.randomUUID()}"
                try {
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
                        initialize(
                            KeyGenParameterSpec
                                .Builder(keyId, KeyProperties.PURPOSE_SIGN)
                                .setDigests(KeyProperties.DIGEST_SHA256)
                                .setKeySize(256)
                                .build(),
                        )
                        generateKeyPair()
                    }
                    isInSecureHardware(getKeyInfo(getPrivateKeyEntry(keyId).privateKey)).also { defaultKeyStorageIsSecure = it }
                } catch (e: Exception) {
                    // A keystore that can't generate a key can't store keys in the TEE either. Not remembered, the
                    // keystore may work again later
                    false
                } finally {
                    runCatching { getKeyStore().deleteEntry(keyId) }
                }
            }

        fun isSecureEnvironmentSupported(
            context: AppContext,
            minimumKeyStorage: KeyStorage,
        ): Boolean =
            when (minimumKeyStorage) {
                KeyStorage.STRONG_BOX ->
                    (context.reactContext ?: throw Exceptions.ReactContextLost())
                        .packageManager
                        .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
                KeyStorage.TRUSTED_ENVIRONMENT -> isDefaultKeyStorageSecure()
                // The default key storage is either the TEE or software, both are accepted
                KeyStorage.SOFTWARE -> true
            }

        fun generateKeypair(
            context: AppContext,
            keyId: String,
            options: GenerateKeypairOptions,
        ) {
            // For the other key storages, where the key ends up is checked after generating it
            if (options.minimumKeyStorage == KeyStorage.STRONG_BOX && !isSecureEnvironmentSupported(context, KeyStorage.STRONG_BOX)) {
                throw SecureEnvironmentNotSupportedException("The device doesn't support the 'strongBox' key storage")
            }
            assertKeyDoesNotExist(keyId)

            // Keys not in StrongBox go to the default key storage: the TEE, or software on devices without a TEE. Apps
            // can't choose between those two
            val keyGenParametersBuilder =
                KeyGenParameterSpec
                    .Builder(keyId, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setKeySize(256)
                    .setIsStrongBoxBacked(options.minimumKeyStorage == KeyStorage.STRONG_BOX)

            // The key attestation certificate chain then contains a key description with this challenge
            options.attestationChallenge?.let { challenge ->
                keyGenParametersBuilder.setAttestationChallenge(challenge.map { it.toByte() }.toByteArray())
            }

            options.userAuthentication?.let { userAuthentication ->
                val authenticators = toAuthenticators(userAuthentication.methods)
                assertUserAuthenticationAvailable(context, authenticators)

                var authenticationTypes = 0
                if (UserAuthenticationMethod.BIOMETRIC in userAuthentication.methods) {
                    authenticationTypes = authenticationTypes or KeyProperties.AUTH_BIOMETRIC_STRONG
                    // The keystore ignores this when the device credential is allowed as well
                    keyGenParametersBuilder.setInvalidatedByBiometricEnrollment(userAuthentication.invalidateOnBiometricChange)
                }
                if (UserAuthenticationMethod.DEVICE_CREDENTIAL in userAuthentication.methods) {
                    authenticationTypes = authenticationTypes or KeyProperties.AUTH_DEVICE_CREDENTIAL
                }

                keyGenParametersBuilder
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(userAuthentication.validitySeconds, authenticationTypes)
            }

            try {
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
                    initialize(keyGenParametersBuilder.build())
                    generateKeyPair()
                }
            } catch (e: StrongBoxUnavailableException) {
                throw SecureEnvironmentNotSupportedException("The device doesn't support the 'strongBox' key storage")
            }

            if (options.minimumKeyStorage != KeyStorage.SOFTWARE && !isInSecureHardware(getKeyInfo(getPrivateKeyEntry(keyId).privateKey))) {
                getKeyStore().deleteEntry(keyId)
                throw SecureEnvironmentNotSupportedException(
                    "The device has no secure hardware to store keys, only software. Use the 'software' minimum key storage to allow that.",
                )
            }
        }

        fun isUserAuthenticationAvailable(
            context: AppContext,
            methods: List<UserAuthenticationMethod>,
        ): Boolean = getUserAuthenticationStatus(context, toAuthenticators(methods)) == BiometricManager.BIOMETRIC_SUCCESS

        // Return where the key is stored: a `KeyStorage` value, or `secureHardware` when Android doesn't say which
        fun getKeyStorage(keyId: String): String = getKeyStorage(getKeyInfo(getPrivateKeyEntry(keyId).privateKey))

        // Return the key attestation certificate chain as base64 encoded DER certificates, leaf first
        fun getAttestationCertificateChain(keyId: String): List<String> {
            val chain = getKeyStore().getCertificateChain(keyId) ?: throw KeyNotFoundException(keyId)

            return chain.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }
        }

        // Return public bytes in DER-encoded (SubjectPublicKeyInfo) format
        fun getPublicBytesForKeyId(keyId: String): ByteArray =
            getPrivateKeyEntry(keyId)
                .certificate.publicKey.encoded

        private fun initSignature(
            keyId: String,
            privateKey: PrivateKey,
        ): Signature =
            try {
                Signature.getInstance(SHA256_WITH_ECDSA_ALGO).apply { initSign(privateKey) }
            } catch (e: KeyPermanentlyInvalidatedException) {
                throw KeyInvalidatedException(keyId, e)
            }

        // Return a signature over the message in DER-encoded (ECDA-sig-Value: r,s) format
        fun sign(
            context: AppContext,
            keyId: String,
            message: ByteArray,
            prompt: AuthenticationPrompt,
            promise: Promise,
        ) {
            promise.rejectOnError {
                val privateKey = getPrivateKeyEntry(keyId).privateKey
                val keyInfo = getKeyInfo(privateKey)

                val signMessage = { signature: Signature ->
                    promise.rejectOnError {
                        signature.update(message)
                        promise.resolve(signature.sign())
                    }
                }

                if (!keyInfo.isUserAuthenticationRequired) {
                    return signMessage(initSignature(keyId, privateKey))
                }

                val userAuthenticationPrompt = UserAuthenticationPrompt(context, prompt, toAuthenticators(keyInfo))

                // The user authentication of a key without validity duration unlocks a single signature
                if (keyInfo.userAuthenticationValidityDurationSeconds <= 0) {
                    return userAuthenticationPrompt.authenticate(
                        initSignature(keyId, privateKey),
                        { result ->
                            result.cryptoObject?.signature?.let(signMessage)
                                ?: promise.reject(CodedException("The authentication prompt didn't return the signature to sign with"))
                        },
                        { error -> promise.reject(error) },
                    )
                }

                // Keys with a validity duration can be used without asking the user again while it lasts
                try {
                    signMessage(initSignature(keyId, privateKey))
                } catch (e: UserNotAuthenticatedException) {
                    userAuthenticationPrompt.authenticate(
                        null,
                        { promise.rejectOnError { signMessage(initSignature(keyId, privateKey)) } },
                        { error -> promise.reject(error) },
                    )
                }
            }
        }

        // Ask the user to authenticate, which unlocks the keys with a validity duration while it lasts
        fun authenticate(
            context: AppContext,
            methods: List<UserAuthenticationMethod>,
            prompt: AuthenticationPrompt,
            promise: Promise,
        ) {
            promise.rejectOnError {
                val authenticators = toAuthenticators(methods)
                assertUserAuthenticationAvailable(context, authenticators)

                UserAuthenticationPrompt(context, prompt, authenticators).authenticate(
                    null,
                    { promise.resolve(UserAuthenticationSession(context)) },
                    { error -> promise.reject(error) },
                )
            }
        }

        // Delete the key from the secure environment
        fun deleteKey(keyId: String) {
            val keyStore = getKeyStore()
            if (!keyStore.containsAlias(keyId)) {
                throw KeyNotFoundException(keyId)
            }

            keyStore.deleteEntry(keyId)
        }
    }
}
