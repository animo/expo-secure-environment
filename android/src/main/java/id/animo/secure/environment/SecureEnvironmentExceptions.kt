package id.animo.secure.environment

import expo.modules.kotlin.exception.CodedException

// The error codes are derived from the class names, e.g. `KeyNotFoundException` becomes `ERR_KEY_NOT_FOUND`.
// The JavaScript side maps these codes to its error classes, so keep the names in sync with `SecureEnvironmentError.ts`.

class SecureEnvironmentNotSupportedException(
    message: String,
) : CodedException(message)

class KeyNotFoundException(
    keyId: String,
) : CodedException("Key '$keyId' not found")

class KeyAlreadyExistsException(
    keyId: String,
) : CodedException("Key '$keyId' already exists")

class KeyInvalidatedException(
    keyId: String,
    cause: Throwable,
) : CodedException(
        "Key '$keyId' was permanently invalidated, which happens when the biometrics on the device change or the screen lock is removed",
        cause,
    )

class UserAuthenticationCanceledException(
    message: String,
) : CodedException(message)

class UserAuthenticationFailedException(
    message: String,
) : CodedException(message)

class UserAuthenticationUnavailableException(
    message: String,
) : CodedException(message)

class UserAuthenticationLockedOutException(
    message: String,
) : CodedException(message)
