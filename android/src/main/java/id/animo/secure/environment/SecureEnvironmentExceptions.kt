package id.animo.secure.environment

class SecureEnvironmentExceptions {
    class NoHardwareKeyStore : Exception("No hardware keystore found")
    class NoKeyWithIdFound(keyId: String) : Exception("key with id: '$keyId' not found")
    class NoSignatureOnCryptoObject :
        Exception("[UNREACHABLE]: Could not get the signature on the crypto object.")

    class NotExecutedFromMainThread : Exception("Function was not called from the main thread")

    class CouldNotGenerateKeyPair : Exception("Could not generate a key pair")
}