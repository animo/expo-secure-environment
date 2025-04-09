export class SecureEnvironmentError extends Error {
  public constructor(message: string, keyId: string, nativeError: string) {
    super(message, { cause: { keyId } })
  }

  static fromNative(keyId: string, error: string) {
    if (error.includes('KeychainQueryError')) {
      return new KeychainQueryError('Error while querying for key', keyId, error)
    }
    if (error.includes('KeyNotFound')) {
      return new KeychainQueryError('Key not found', keyId, error)
    }
    if (error.includes('KeyAlreadyExists')) {
      return new KeyAlreadyExistsError('Key already exists', keyId, error)
    }
    if (error.includes('CouldNotConvertIntoPublicKey')) {
      return new CouldNotConvertIntoPublicKey('Could not convert key into public key', keyId, error)
    }
    if (error.includes('CouldNotConvertSignatureToRaw')) {
      return new CouldNotConvertIntoExternalRepresentation(
        'Could not convert the signature into its raw format',
        keyId,
        error
      )
    }
    if (error.includes('CouldNotCreateSignature')) {
      return new CouldNotCreateSignature('An error occurred ', keyId, error)
    }
    if (error.includes('BiometricAuthenticationFailed')) {
      return new BiometricAuthenticationFailed('Biometric Authentication Failed', keyId, error)
    }
    if (error.includes('NoHardwareKeyStore')) {
      return new NoHardwareKeyStore('No support for the hardware key store', keyId, error)
    }
    if (error.includes('NoSignatureOnCryptoObject')) {
      return new NoSignatureOnCryptoObject('No signature on the crypto object', keyId, error)
    }
    if (error.includes('NotExecutedFromMainThread')) {
      return new NotExecutedFromMainThread('Function must be executed from the main thread', keyId, error)
    }
    if (error.includes('CouldNotGenerateKeyPair')) {
      return new CouldNotGenerateKeyPair('Could not generate the key pair', keyId, error)
    }

    return new SecureEnvironmentError('Unable to determine error', keyId, error)
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
