export class SecureEnvironmentError extends Error {
  public constructor(
    message: string,
    public keyId: string,
    public nativeError: string
  ) {
    super(message)
  }

  public toJSON() {
    return {
      message: this.message,
      keyId: this.keyId,
      nativeError: this.nativeError,
    }
  }

  static fromNative(keyId: string, error: string) {
    if (error.includes('KeychainQueryError')) {
      return new KeychainQueryError(`Error while querying for key ${keyId}: ${error}`, keyId, error)
    }
    if (error.includes('KeyNotFound')) {
      return new KeyNotFoundError(`Key ${keyId} not found: ${error}`, keyId, error)
    }
    if (error.includes('KeyAlreadyExists')) {
      return new KeyAlreadyExistsError(`Key ${keyId} already exists: ${error}`, keyId, error)
    }
    if (error.includes('CouldNotConvertIntoPublicKey')) {
      return new CouldNotConvertIntoPublicKey(`Could not convert key ${keyId} into public key: ${error}`, keyId, error)
    }
    if (error.includes('CouldNotConvertSignatureToRaw')) {
      return new CouldNotConvertIntoExternalRepresentation(
        `Could not convert the signature into its raw format: ${error}`,
        keyId,
        error
      )
    }
    if (error.includes('CouldNotCreateSignature')) {
      return new CouldNotCreateSignature(
        `An error occurred while creating a signature with key ${keyId}: ${error}`,
        keyId,
        error
      )
    }
    if (error.includes('BiometricAuthenticationFailed')) {
      return new BiometricAuthenticationFailed(
        `Biometric Authentication Failed for key ${keyId}: ${error}`,
        keyId,
        error
      )
    }
    if (error.includes('NoHardwareKeyStore')) {
      return new NoHardwareKeyStore(`No support for the hardware key store: ${error}`, keyId, error)
    }
    if (error.includes('NoSignatureOnCryptoObject')) {
      return new NoSignatureOnCryptoObject(`No signature on the crypto object: ${error}`, keyId, error)
    }
    if (error.includes('NotExecutedFromMainThread')) {
      return new NotExecutedFromMainThread(`Function must be executed from the main thread: ${error}`, keyId, error)
    }
    if (error.includes('CouldNotGenerateKeyPair')) {
      return new CouldNotGenerateKeyPair(`Could not generate the key pair: ${error}`, keyId, error)
    }

    return new SecureEnvironmentError(`Unable to determine error: ${error}`, keyId, error)
  }
}

export class KeychainQueryError extends SecureEnvironmentError {}

export class KeyNotFoundError extends SecureEnvironmentError {}
export class KeyAlreadyExistsError extends SecureEnvironmentError {}

export class CouldNotConvertIntoPublicKey extends SecureEnvironmentError {}
export class CouldNotCreateSignature extends SecureEnvironmentError {}
export class CouldNotConvertIntoExternalRepresentation extends SecureEnvironmentError {}
export class BiometricAuthenticationFailed extends SecureEnvironmentError {}

export class NoHardwareKeyStore extends SecureEnvironmentError {}
export class NoSignatureOnCryptoObject extends SecureEnvironmentError {}
export class NotExecutedFromMainThread extends SecureEnvironmentError {}
export class CouldNotGenerateKeyPair extends SecureEnvironmentError {}
