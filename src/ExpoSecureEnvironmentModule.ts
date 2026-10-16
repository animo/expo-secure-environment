import { type SharedObject, requireNativeModule } from 'expo'
import type { AuthenticationPrompt, KeyStorage, StoredKeyStorage, UserAuthenticationMethod } from './types'

// The options as the native modules receive them, with the defaults filled in
export interface NativeGenerateKeypairOptions {
  userAuthentication?: {
    methods: UserAuthenticationMethod[]
    invalidateOnBiometricChange: boolean
    validitySeconds: number
  }
  minimumKeyStorage: KeyStorage
  // The bytes of the challenge. A Uint8Array inside an object doesn't reach the native side as bytes
  attestationChallenge?: number[]
}

export type NativeAuthenticationPrompt = Required<Omit<AuthenticationPrompt, 'subtitle'>> &
  Pick<AuthenticationPrompt, 'subtitle'>

// The authentication of `authenticate`. Signing with it reuses the authentication on iOS, releasing it ends the
// authentication there
export declare class NativeUserAuthenticationSession extends SharedObject {}

interface ExpoSecureEnvironmentModule {
  isSecureEnvironmentSupported(minimumKeyStorage: KeyStorage): boolean
  isUserAuthenticationAvailable(methods: UserAuthenticationMethod[]): boolean
  generateKeypair(keyId: string, options: NativeGenerateKeypairOptions): void
  // Returns the compressed public key on iOS, and the DER encoded SubjectPublicKeyInfo on Android
  getPublicBytesForKeyId(keyId: string): Uint8Array
  // Only available on Android
  getKeyStorage(keyId: string): StoredKeyStorage
  // Only available on Android
  getAttestationCertificateChain(keyId: string): string[]
  // Returns a DER encoded ECDSA-Sig-Value
  sign(
    keyId: string,
    message: Uint8Array,
    prompt: NativeAuthenticationPrompt,
    session?: NativeUserAuthenticationSession
  ): Promise<Uint8Array>
  authenticate(
    methods: UserAuthenticationMethod[],
    prompt: NativeAuthenticationPrompt
  ): Promise<NativeUserAuthenticationSession>
  deleteKey(keyId: string): void
}

export const expoSecureEnvironment = requireNativeModule<ExpoSecureEnvironmentModule>('ExpoSecureEnvironment')
