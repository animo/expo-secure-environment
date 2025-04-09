/**
 * These changes are made in this way so the interface does not change.
 * It would be good to change this down the line and credo-ts gets a rework on
 * the crypto interfaces.
 *
 */

import { Platform } from 'expo-modules-core'
import { expoSecureEnvironment } from './ExpoSecureEnvironmentModule'

export interface SecureEnvironment {
  generateKeypair(keyId: string, biometricsBacked?: boolean): Promise<Uint8Array> | Uint8Array
  /**
   *
   * @todo Might be better to make this optional
   *
   * Returns an object where each key is the `keyId` and the value is the public key bytes
   *
   */
  batchGenerateKeyPair(
    keyIds: Array<string>,
    biometricsBacked?: boolean
  ): Promise<Record<string, Uint8Array>> | Record<string, Uint8Array>
  getPublicBytesForKeyId(keyId: string): Promise<Uint8Array> | Uint8Array
  sign(keyId: string, message: Uint8Array, biometricsBacked?: boolean): Promise<Uint8Array>
  deleteKey(keyId: string): Promise<void> | void
}

export let isExpoSecureEnvironmentSupported: boolean
let fallbackSecureEnvironment: SecureEnvironment
export const setFallbackSecureEnvironment = (env: SecureEnvironment) => {
  fallbackSecureEnvironment = env
}
export const getSecureEnvironment = () => {
  // Caching mechanism so we do not check it before every call
  if (isExpoSecureEnvironmentSupported === undefined) {
    isExpoSecureEnvironmentSupported = expoSecureEnvironment.supportsSecureEnvironment()
  }

  // When the local secure environment is supported, it is returned
  if (isExpoSecureEnvironmentSupported) return expoSecureEnvironment

  // Error out when the local secure environment is not supported and no fallback is provided
  if (!fallbackSecureEnvironment) {
    throw new Error(
      'Could not use local secure environment and fallback secure environment is not set. Call `setFallackSecureEnvironment(env: SecureEnvironment)`'
    )
  }

  return fallbackSecureEnvironment
}

export const shouldUseFallbackSecureEnvironment = (useFallback: boolean) => {
  isExpoSecureEnvironmentSupported = !useFallback
}

export const isLocalSecureEnvironmentSupported = () =>
  Platform.OS === 'ios' ? true : expoSecureEnvironment.supportsSecureEnvironment()
