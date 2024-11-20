/**
 * These changes are made in this way so the interface does not change.
 * It would be good to change this down the line and credo-ts gets a rework on
 * the crypto interfaces.
 *
 */

import { Platform, requireNativeModule } from 'expo-modules-core'

const expoSecureEnvironment = requireNativeModule<SecureEnvironment & { supportsSecureEnvironment: () => boolean }>(
  'ExpoSecureEnvironment'
)

export interface SecureEnvironment {
  generateKeypair(id: string, biometricsBacked?: boolean): Promise<void> | void
  getPublicBytesForKeyId(keyId: string): Promise<Uint8Array> | Uint8Array
  sign(keyId: string, message: Uint8Array, biometricsBacked?: boolean): Promise<Uint8Array>
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
