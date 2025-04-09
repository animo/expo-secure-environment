package id.animo.secure.environment

class SecureEnvironmentExceptions {
    class NoHardwareKeyStore : Exception("NoHardwareKeyStore")

    class KeyNotFound(
        keyId: String,
    ) : Exception("KeyNotFound")

    class KeyAlreadyExists(
        keyId: String,
    ) : Exception("KeyAlreadyExists")

    class NoSignatureOnCryptoObject : Exception("NoSignatureOnCryptoObject")

    class NotExecutedFromMainThread : Exception("NotExecutedFromMainThread")

    class CouldNotGenerateKeyPair : Exception("CouldNotGenerateKeyPair")
}
