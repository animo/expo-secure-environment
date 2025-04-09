import { requireNativeModule } from 'expo-modules-core'
import { Platform } from 'react-native'
import type { SecureEnvironment } from './SecureEnvironment'

type UnwrapPromiseReturnTypes<T, ExcludedKey extends keyof T = never> = {
  [K in keyof T]: K extends ExcludedKey
    ? T[K]
    : T[K] extends (...args: infer A) => Promise<infer R> | infer S
      ? (...args: A) => Promise<R> extends Promise<infer U> ? U : Promise<R> | S
      : T[K]
}

const nativeExpoSecureEnvironment = requireNativeModule<
  UnwrapPromiseReturnTypes<Omit<SecureEnvironment, 'batchGenerateKeyPair'>, 'sign'> & {
    supportsSecureEnvironment: () => boolean
  }
>('ExpoSecureEnvironment')

export const expoSecureEnvironment = {
  generateKeypair: (keyId: string, biometricsBacked?: boolean): Uint8Array => {
    nativeExpoSecureEnvironment.generateKeypair(keyId, biometricsBacked)
    const publicKey = expoSecureEnvironment.getPublicBytesForKeyId(keyId)
    return publicKey
  },

  batchGenerateKeyPair: (keyIds: Array<string>): Record<string, Uint8Array> => {
    for (const keyId of keyIds) {
      expoSecureEnvironment.generateKeypair(keyId)
    }

    return keyIds
      .map((keyId) => ({
        keyId,
        publicKey: expoSecureEnvironment.getPublicBytesForKeyId(keyId),
      }))
      .reduce((prev, curr) => ({ ...prev, [curr.keyId]: curr.publicKey }), {})
  },

  getPublicBytesForKeyId: (keyId: string): Uint8Array => {
    return nativeExpoSecureEnvironment.getPublicBytesForKeyId(keyId)
  },

  sign: (keyId: string, message: Uint8Array, biometricsBacked?: boolean): Promise<Uint8Array> => {
    return Platform.OS === 'ios'
      ? nativeExpoSecureEnvironment.sign(keyId, message)
      : nativeExpoSecureEnvironment.sign(keyId, message, biometricsBacked)
  },

  supportsSecureEnvironment: () => {
    return nativeExpoSecureEnvironment.supportsSecureEnvironment()
  },

  deleteKey: (keyId: string) => {
    return nativeExpoSecureEnvironment.deleteKey(keyId)
  },
}
