import ExpoModulesCore
import LocalAuthentication

// The error codes are derived from the class names, e.g. `KeyNotFoundException` becomes `ERR_KEY_NOT_FOUND`.
// The JavaScript side maps these codes to its error classes, so keep the names in sync with `SecureEnvironmentError.ts`.

final class SecureEnvironmentNotSupportedException: Exception, @unchecked Sendable {
  override var reason: String {
    "The Secure Enclave is not available on this device"
  }
}

final class KeyNotFoundException: GenericException<String>, @unchecked Sendable {
  override var reason: String {
    "Key '\(param)' not found"
  }
}

final class KeyAlreadyExistsException: GenericException<String>, @unchecked Sendable {
  override var reason: String {
    "Key '\(param)' already exists"
  }
}

final class UserAuthenticationCanceledException: GenericException<String>, @unchecked Sendable {
  override var reason: String {
    param
  }
}

final class UserAuthenticationFailedException: GenericException<String>, @unchecked Sendable {
  override var reason: String {
    param
  }
}

final class UserAuthenticationUnavailableException: GenericException<String>, @unchecked Sendable {
  override var reason: String {
    param
  }
}

final class UserAuthenticationLockedOutException: GenericException<String>, @unchecked Sendable {
  override var reason: String {
    param
  }
}

final class SecureEnvironmentException: GenericException<String>, @unchecked Sendable {
  override var reason: String {
    param
  }
}

// Errors of the TKError domain of CryptoTokenKit, which Secure Enclave operations use
private let cryptoTokenKitErrorDomain = "CryptoTokenKit"
private let cryptoTokenKitCanceledByUser = -4
private let cryptoTokenKitAuthenticationFailed = -5

/// Converts an error of LocalAuthentication, or of a key operation that required user authentication, to the
/// exception for the JavaScript side. Returns nil for other errors.
func toUserAuthenticationException(_ error: Error) -> Exception? {
  let nsError = error as NSError
  let message = nsError.localizedDescription

  if nsError.domain == LAErrorDomain, let code = LAError.Code(rawValue: nsError.code) {
    switch code {
    case .userCancel, .systemCancel, .appCancel, .userFallback:
      return UserAuthenticationCanceledException(message)
    case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet:
      return UserAuthenticationUnavailableException(message)
    // Biometrics work again after the user enters the device passcode
    case .biometryLockout:
      return UserAuthenticationLockedOutException(message)
    default:
      return UserAuthenticationFailedException(message)
    }
  }

  if (nsError.domain == NSOSStatusErrorDomain && nsError.code == Int(errSecUserCanceled))
    || (nsError.domain == cryptoTokenKitErrorDomain && nsError.code == cryptoTokenKitCanceledByUser)
  {
    return UserAuthenticationCanceledException(message)
  }

  if (nsError.domain == NSOSStatusErrorDomain && nsError.code == Int(errSecAuthFailed))
    || (nsError.domain == cryptoTokenKitErrorDomain && nsError.code == cryptoTokenKitAuthenticationFailed)
  {
    return UserAuthenticationFailedException(message)
  }

  if let underlyingError = nsError.userInfo[NSUnderlyingErrorKey] as? Error {
    return toUserAuthenticationException(underlyingError)
  }

  return nil
}
