enum SecureEnvironmentError: Error {
  case KeychainQueryError(String?)
  case KeyNotFound(String)
  case KeyAlreadyExists(String)
  case CouldNotConvertIntoPublicKey
  case CouldNotConvertSignatureToRaw
  case BiometricAuthenticationFailed
  case CouldNotCreateSignature
}

extension SecureEnvironmentError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .KeychainQueryError(_):
      NSLocalizedString("KeychainQueryError", comment: "")
    case .KeyNotFound(_):
      NSLocalizedString("KeyNotFound", comment: "")
    case .KeyAlreadyExists(_):
      NSLocalizedString("KeyAlreadyExists", comment: "")
    case .CouldNotConvertIntoPublicKey:
      NSLocalizedString("CouldNotConvertIntoPublicKey", comment: "")`
    case .CouldNotConvertSignatureToRaw:
      NSLocalizedString("CouldNotConvertSignatureToRaw", comment: "")
    case .BiometricAuthenticationFailed:
      NSLocalizedString("BiometricAuthenticationFailed", comment: "")
    case .CouldNotCreateSignature:
      NSLocalizedString("CouldNotCreateSignature", comment: "")
    }
  }
}
