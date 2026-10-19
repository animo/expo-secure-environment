export interface SecureEnvironmentErrorOptions {
  keyId?: string
  code?: string
  cause?: unknown
}

/**
 * Base class of the errors thrown by this library. Errors that have no more specific class are thrown as this class.
 */
export class SecureEnvironmentError extends Error {
  public name = 'SecureEnvironmentError'

  /**
   * The id of the key the operation was for, if any.
   */
  public keyId?: string

  /**
   * The error code from the native module, if the error came from there.
   */
  public code?: string

  public constructor(message: string, options: SecureEnvironmentErrorOptions = {}) {
    super(message)
    this.keyId = options.keyId
    this.code = options.code
    this.cause = options.cause
  }

  public toJSON() {
    return {
      name: this.name,
      message: this.message,
      keyId: this.keyId,
      code: this.code,
    }
  }
}

/**
 * The device has no secure environment to store keys: no Secure Enclave on iOS (e.g. the simulator), or not the
 * requested key storage on Android. Also thrown by every function that uses keys below Android 11.
 */
export class SecureEnvironmentNotSupportedError extends SecureEnvironmentError {
  public name = 'SecureEnvironmentNotSupportedError'
}

export class KeyNotFoundError extends SecureEnvironmentError {
  public name = 'KeyNotFoundError'
}

export class KeyAlreadyExistsError extends SecureEnvironmentError {
  public name = 'KeyAlreadyExistsError'
}

/**
 * The key was permanently invalidated. Android invalidates keys that require user authentication when the screen lock
 * is removed or reset, and keys generated with `invalidateOnBiometricChange` when the biometrics on the device change.
 * Delete the key and generate a new one.
 *
 * Only thrown on Android.
 */
export class KeyInvalidatedError extends SecureEnvironmentError {
  public name = 'KeyInvalidatedError'
}

/**
 * The user, the app or the system canceled the authentication prompt.
 */
export class UserAuthenticationCanceledError extends SecureEnvironmentError {
  public name = 'UserAuthenticationCanceledError'
}

/**
 * The user didn't authenticate successfully, for example because the biometrics weren't recognized.
 */
export class UserAuthenticationFailedError extends SecureEnvironmentError {
  public name = 'UserAuthenticationFailedError'
}

/**
 * Biometrics are locked after too many failed attempts. They unlock when the user enters the device passcode, and on
 * Android a first lockout also ends after 30 seconds.
 */
export class UserAuthenticationLockedOutError extends SecureEnvironmentError {
  public name = 'UserAuthenticationLockedOutError'
}

/**
 * The user can't authenticate with the requested methods, for example because no biometrics are enrolled or no
 * device passcode is set.
 */
export class UserAuthenticationUnavailableError extends SecureEnvironmentError {
  public name = 'UserAuthenticationUnavailableError'
}

// The native modules derive these codes from their exception class names, e.g. `KeyNotFoundException`
const errorClassesByCode: Record<string, typeof SecureEnvironmentError> = {
  ERR_SECURE_ENVIRONMENT_NOT_SUPPORTED: SecureEnvironmentNotSupportedError,
  ERR_KEY_NOT_FOUND: KeyNotFoundError,
  ERR_KEY_ALREADY_EXISTS: KeyAlreadyExistsError,
  ERR_KEY_INVALIDATED: KeyInvalidatedError,
  ERR_USER_AUTHENTICATION_CANCELED: UserAuthenticationCanceledError,
  ERR_USER_AUTHENTICATION_FAILED: UserAuthenticationFailedError,
  ERR_USER_AUTHENTICATION_LOCKED_OUT: UserAuthenticationLockedOutError,
  ERR_USER_AUTHENTICATION_UNAVAILABLE: UserAuthenticationUnavailableError,
}

// Native errors read "Calling the 'deleteKey' function has failed\n→ Caused by: <reason>" (iOS) or "Call to function
// 'ExpoSecureEnvironment.deleteKey' has been rejected.\n→ Caused by: <reason>" (Android). iOS debug builds add the
// exception class and location: "KeyNotFoundException: <reason> (at utils.swift:46)". Only the reason is kept, the
// native error stays in `cause`
const toReason = (message: string) =>
  (message.split('→ Caused by: ').pop() ?? message)
    .trim()
    .replace(/^\w+Exception: /, '')
    .replace(/ \(at [^)]*\)$/, '')

export function toSecureEnvironmentError(error: unknown, keyId?: string): SecureEnvironmentError {
  if (error instanceof SecureEnvironmentError) return error

  const code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : undefined
  const message = error instanceof Error ? error.message : String(error)
  const ErrorClass = (code && errorClassesByCode[code]) || SecureEnvironmentError

  return new ErrorClass(code ? toReason(message) : message, { keyId, code, cause: error })
}
