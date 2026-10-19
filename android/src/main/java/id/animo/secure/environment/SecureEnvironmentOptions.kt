package id.animo.secure.environment

import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import expo.modules.kotlin.types.Enumerable

enum class KeyStorage(
    val value: String,
) : Enumerable {
    STRONG_BOX("strongBox"),
    TRUSTED_ENVIRONMENT("trustedEnvironment"),
    SOFTWARE("software"),
}

enum class UserAuthenticationMethod(
    val value: String,
) : Enumerable {
    BIOMETRIC("biometric"),
    DEVICE_CREDENTIAL("deviceCredential"),
}

class UserAuthenticationOptions : Record {
    @Field
    val methods: List<UserAuthenticationMethod> = listOf(UserAuthenticationMethod.BIOMETRIC)

    @Field
    val invalidateOnBiometricChange: Boolean = true

    @Field
    val validitySeconds: Int = 0
}

class GenerateKeypairOptions : Record {
    // Null when signing doesn't require user authentication
    @Field
    val userAuthentication: UserAuthenticationOptions? = null

    @Field
    val minimumKeyStorage: KeyStorage = KeyStorage.STRONG_BOX

    @Field
    val preferStrongBox: Boolean = true

    // The bytes of the challenge. A Uint8Array inside a record isn't converted to a ByteArray, so JS sends a list
    @Field
    val attestationChallenge: List<Int>? = null
}

class AuthenticationPrompt : Record {
    @Field
    val title: String = "Authenticate to sign data"

    @Field
    val subtitle: String? = null

    @Field
    val cancel: String = "Cancel"
}
