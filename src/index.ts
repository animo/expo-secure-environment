import { ECDSASigValue } from '@peculiar/asn1-ecc'
import { AsnParser } from '@peculiar/asn1-schema'
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509'
import { Platform } from 'react-native'
import {
  type NativeAuthenticationPrompt,
  type NativeUserAuthenticationSession,
  expoSecureEnvironment,
} from './ExpoSecureEnvironmentModule'
import { SecureEnvironmentError, toSecureEnvironmentError } from './SecureEnvironmentError'
import type {
  AuthenticationPrompt,
  GenerateKeypairOptions,
  IsSecureEnvironmentSupportedOptions,
  IsUserAuthenticationAvailableOptions,
  SignOptions,
  StoredKeyStorage,
  UserAuthenticationSession,
  WithUserAuthenticationOptions,
} from './types'

export {
  SecureEnvironmentError,
  SecureEnvironmentNotSupportedError,
  KeyNotFoundError,
  KeyAlreadyExistsError,
  KeyInvalidatedError,
  UserAuthenticationCanceledError,
  UserAuthenticationFailedError,
  UserAuthenticationLockedOutError,
  UserAuthenticationUnavailableError,
} from './SecureEnvironmentError'
export type { SecureEnvironmentErrorOptions } from './SecureEnvironmentError'
export type * from './types'

const toNativePrompt = (prompt: AuthenticationPrompt = {}): NativeAuthenticationPrompt => ({
  title: prompt.title ?? 'Authenticate to sign data',
  subtitle: prompt.subtitle,
  cancel: prompt.cancel ?? 'Cancel',
})

/**
 * Whether the device can store keys in a secure environment: the Secure Enclave on iOS, or at least the requested
 * minimum key storage on Android. Without it, {@link generateKeypair} throws a `SecureEnvironmentNotSupportedError`.
 *
 * On Android checking the TEE generates and deletes a key once, because only a generated key tells whether the
 * device stores keys in the TEE or in software. Always `false` below Android 11.
 */
export function isSecureEnvironmentSupported(options: IsSecureEnvironmentSupportedOptions = {}): boolean {
  try {
    return expoSecureEnvironment.isSecureEnvironmentSupported(options.minimumKeyStorage ?? 'strongBox')
  } catch (error) {
    throw toSecureEnvironmentError(error)
  }
}

/**
 * Whether the user can authenticate with the `methods`: biometrics are enrolled, or a device passcode is set. Without
 * it, {@link generateKeypair} with these methods throws a `UserAuthenticationUnavailableError`.
 *
 * Also `false` on iOS while biometrics are locked after too many failed attempts, and always `false` below Android 11.
 */
export function isUserAuthenticationAvailable(options: IsUserAuthenticationAvailableOptions = {}): boolean {
  try {
    return expoSecureEnvironment.isUserAuthenticationAvailable(options.methods ?? ['biometric'])
  } catch (error) {
    throw toSecureEnvironmentError(error)
  }
}

/**
 * Generates a P-256 key pair in the secure environment of the device. The private key never leaves it.
 *
 * By default signing requires biometric authentication every time. Change this, and on Android where the key is
 * stored, with the `options`.
 *
 * @throws {SecureEnvironmentNotSupportedError} the device doesn't support the key storage
 * @throws {UserAuthenticationUnavailableError} the device can't authenticate the user with the requested methods
 * @throws {UserAuthenticationLockedOutError} biometrics are locked after too many failed attempts (iOS)
 * @throws {KeyAlreadyExistsError} a key with this id already exists
 */
export async function generateKeypair(keyId: string, options: GenerateKeypairOptions = {}): Promise<void> {
  const { userAuthentication = {}, minimumKeyStorage = 'strongBox', attestationChallenge } = options

  try {
    expoSecureEnvironment.generateKeypair(keyId, {
      userAuthentication: userAuthentication
        ? {
            methods: userAuthentication.methods ?? ['biometric'],
            invalidateOnBiometricChange: userAuthentication.invalidateOnBiometricChange ?? true,
            validitySeconds: userAuthentication.validitySeconds ?? 0,
          }
        : undefined,
      minimumKeyStorage,
      attestationChallenge: attestationChallenge ? Array.from(attestationChallenge) : undefined,
    })
  } catch (error) {
    throw toSecureEnvironmentError(error, keyId)
  }
}

/**
 * Returns where the key is stored: `strongBox`, `trustedEnvironment` or `software`, or `secureHardware` when Android
 * only tells that the key is in secure hardware (always on Android 11). With a `minimumKeyStorage` below `strongBox`
 * this is the only way to know where a key ended up, apart from its key attestation.
 *
 * Only available on Android, iOS keys are always stored in the Secure Enclave.
 *
 * @throws {KeyNotFoundError} no key with this id exists
 */
export async function getKeyStorage(keyId: string): Promise<StoredKeyStorage> {
  if (Platform.OS !== 'android') {
    throw new SecureEnvironmentError('The key storage is only available on Android', { keyId })
  }

  try {
    return expoSecureEnvironment.getKeyStorage(keyId)
  } catch (error) {
    throw toSecureEnvironmentError(error, keyId)
  }
}

/**
 * Returns the key attestation of a key generated with an `attestationChallenge`: a certificate chain from the secure
 * hardware that proves the key was generated there, with how it is protected and the challenge. The certificates are
 * base64 encoded DER, leaf first.
 *
 * Only available on Android, iOS has no key attestation for Secure Enclave keys.
 */
export async function getAttestationCertificateChain(keyId: string): Promise<string[]> {
  if (Platform.OS !== 'android') {
    throw new SecureEnvironmentError('Key attestation is only available on Android', { keyId })
  }

  try {
    return expoSecureEnvironment.getAttestationCertificateChain(keyId)
  } catch (error) {
    throw toSecureEnvironmentError(error, keyId)
  }
}

/**
 * Returns the public key in compressed form (33 bytes).
 *
 * @throws {KeyNotFoundError} no key with this id exists
 */
export async function getPublicBytesForKeyId(keyId: string): Promise<Uint8Array> {
  try {
    const publicBytes = expoSecureEnvironment.getPublicBytesForKeyId(keyId)
    let key = publicBytes

    if (key.length > 65) {
      // Try to parse it from the ASN.1 SPKI format
      const spki = AsnParser.parse(publicBytes, SubjectPublicKeyInfo)
      key = new Uint8Array(spki.subjectPublicKey)
    }

    if (key.length === 65 && key[0] !== 0x04) {
      throw new Error('Invalid uncompressed key prefix')
    }

    if (key.length === 65) {
      // Extract the X and Y coordinates
      const x = key.slice(1, 33) // bytes 1 to 32 (X coordinate)
      const y = key.slice(33, 65) // bytes 33 to 64 (Y coordinate)
      // Determine the parity of the Y coordinate
      const prefix = (y[y.length - 1] as number) % 2 === 0 ? 0x02 : 0x03
      // Return the compressed key (prefix + X coordinate)
      const compressedKey = new Uint8Array(33)
      compressedKey[0] = prefix
      compressedKey.set(x, 1)
      key = compressedKey
    }

    if (key.length === 33 && key[0] !== 0x03 && key[0] !== 0x02) {
      throw new Error('Invalid compressed key prefix')
    }

    if (key.length !== 33) {
      throw new Error(
        `After attempting key compression, the key has an invalid length. Expected: '33', Received: '${key.length}'`
      )
    }

    return key
  } catch (error) {
    throw toSecureEnvironmentError(error, keyId)
  }
}

// DER integers are variable length: strip the sign byte when present and left-pad
// with zeros so r and s are always exactly `length` bytes in the raw signature
const toFixedLength = (value: ArrayBuffer, length = 32): Uint8Array => {
  const bytes = new Uint8Array(value)
  if (bytes.length >= length) return bytes.slice(bytes.length - length)
  const padded = new Uint8Array(length)
  padded.set(bytes, length - bytes.length)
  return padded
}

const signWithSession = async (
  keyId: string,
  message: Uint8Array,
  options: SignOptions,
  session?: NativeUserAuthenticationSession
): Promise<Uint8Array> => {
  try {
    const signature = await expoSecureEnvironment.sign(keyId, message, toNativePrompt(options.prompt), session)

    const { r, s } = AsnParser.parse(signature, ECDSASigValue)
    return new Uint8Array([...toFixedLength(r), ...toFixedLength(s)])
  } catch (error) {
    throw toSecureEnvironmentError(error, keyId)
  }
}

/**
 * Signs the message with ECDSA and SHA-256, and returns the raw signature (r and s, 64 bytes).
 *
 * When the key requires user authentication, the user is asked to authenticate first. On Android this doesn't
 * happen when the user authenticated within the `validitySeconds` of the key. To sign multiple times with one
 * authentication, use the `sign` that {@link withUserAuthentication} passes to its callback.
 *
 * Wait for a signature that shows a prompt before you start the next one. On iOS a second prompt cancels the first.
 *
 * @throws {KeyNotFoundError} no key with this id exists
 * @throws {KeyInvalidatedError} the key can't be used anymore because the biometrics changed (Android)
 * @throws {UserAuthenticationCanceledError} the authentication prompt was canceled
 * @throws {UserAuthenticationFailedError} the user didn't authenticate successfully
 * @throws {UserAuthenticationLockedOutError} biometrics are locked after too many failed attempts
 */
export async function sign(keyId: string, message: Uint8Array, options: SignOptions = {}): Promise<Uint8Array> {
  return signWithSession(keyId, message, options)
}

/**
 * Asks the user to authenticate once, and then runs `callback`. The `sign` that the callback gets uses this
 * authentication instead of asking the user again. Use this to create multiple signatures with one authentication,
 * for example when presenting multiple credentials.
 *
 * Only that `sign` uses the authentication, and only until the callback returns. Other {@link sign} calls still ask
 * the user, also while the callback runs, and every `withUserAuthentication` call asks the user. Pass the `sign` on
 * to share the authentication.
 *
 * - iOS: works for every key generated with the same `methods`.
 * - Android: only works for keys generated with `userAuthentication.validitySeconds` above `0`, for as long as that
 *   validity lasts. Keys with a validity of `0` require authentication for every signature, also here. Android
 *   can't limit the authentication to this `sign`: until the validity ends, every signature with these keys skips
 *   the prompt.
 *
 * @throws {UserAuthenticationUnavailableError} the device can't authenticate the user with the requested methods
 * @throws {UserAuthenticationCanceledError} the authentication prompt was canceled
 * @throws {UserAuthenticationFailedError} the user didn't authenticate successfully
 * @throws {UserAuthenticationLockedOutError} biometrics are locked after too many failed attempts
 */
export async function withUserAuthentication<T>(
  callback: (session: UserAuthenticationSession) => Promise<T>,
  options: WithUserAuthenticationOptions = {}
): Promise<T> {
  const nativeSession = await expoSecureEnvironment
    .authenticate(options.methods ?? ['biometric'], toNativePrompt(options.prompt))
    .catch((error) => {
      throw toSecureEnvironmentError(error)
    })

  let hasEnded = false
  try {
    return await callback({
      sign: async (keyId, message, signOptions = {}) => {
        if (hasEnded) {
          throw new SecureEnvironmentError('The user authentication has ended, sign inside the callback instead', {
            keyId,
          })
        }
        return signWithSession(keyId, message, signOptions, nativeSession)
      },
    })
  } finally {
    hasEnded = true
    // Ends the authentication on iOS, the context of the session can't sign anymore
    nativeSession.release()
  }
}

/**
 * Deletes the key from the secure environment.
 *
 * @throws {KeyNotFoundError} no key with this id exists
 */
export async function deleteKey(keyId: string): Promise<void> {
  try {
    expoSecureEnvironment.deleteKey(keyId)
  } catch (error) {
    throw toSecureEnvironmentError(error, keyId)
  }
}
