enum SecureEnvironmentError: Error {
  case KeychainQueryError(String?)
  case NoKeyFoundWithId(String)
  case CouldNotConvertIntoPublicKey
  case CouldNotConvertIntoExternalRepresentation
  case CouldNotConvertSignatureToRaw
  case BiometricAuthenticationFailed
}
