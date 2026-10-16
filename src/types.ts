/**
 * A way the user can authenticate to use a key.
 *
 * - `biometric`: strong biometrics. Face ID or Touch ID on iOS, Class 3 biometrics (e.g. fingerprint) on Android.
 * - `deviceCredential`: the device passcode on iOS, the PIN, pattern or password of the lock screen on Android.
 */
export type UserAuthenticationMethod = 'biometric' | 'deviceCredential'

/**
 * Where an Android key is stored, from most to least secure.
 *
 * - `strongBox`: StrongBox, a separate secure element with its own processor and storage. More resistant to
 *   physical attacks, but not every device has one.
 * - `trustedEnvironment`: the Trusted Execution Environment (TEE), an isolated part of the main processor. Most
 *   Android devices have one.
 * - `software`: the Android keystore without secure hardware, on devices without a TEE such as emulators. Apps can't
 *   read the private key, but Android itself can, so it's not protected against a compromised (e.g. rooted) device.
 *
 * Apps can only choose to use StrongBox. All other keys are stored in the default key storage of the device: the TEE,
 * or software on devices without a TEE.
 *
 * On iOS keys are always stored in the Secure Enclave.
 */
export type KeyStorage = 'strongBox' | 'trustedEnvironment' | 'software'

export interface UserAuthenticationOptions {
  /**
   * The ways the user can authenticate. With both, the user can choose either.
   *
   * @default ['biometric']
   */
  methods?: [UserAuthenticationMethod, ...UserAuthenticationMethod[]]

  /**
   * Whether the key becomes permanently unusable when the biometrics on the device change, for example when a
   * fingerprint or face is added. Then someone who knows the device passcode can't add their own biometrics to use
   * the key.
   *
   * Only applies when `methods` is `['biometric']`. When the device credential can also unlock the key, someone who
   * knows it can already use the key.
   *
   * @default true
   */
  invalidateOnBiometricChange?: boolean

  /**
   * The number of seconds the key can be used after the user authenticated, without authenticating again. With `0`
   * every signature requires authentication.
   *
   * Android keys need a validity above `0` to sign multiple times after one authentication, see
   * `withUserAuthentication`. iOS has no validity per key, use `withUserAuthentication` instead.
   *
   * A validity above `0` is less secure. With `0` the authentication unlocks exactly one signature, enforced by the
   * secure hardware. With a validity, any code in the app can sign without a prompt until the validity ends.
   * Any authentication with one of the `methods` starts the validity, including unlocking the device. Keep it short.
   *
   * @default 0
   * @platform android
   */
  validitySeconds?: number
}

export interface GenerateKeypairOptions {
  /**
   * The user authentication needed to sign with the key, or `false` to sign without user authentication.
   *
   * @default { methods: ['biometric'], invalidateOnBiometricChange: true, validitySeconds: 0 }
   */
  userAuthentication?: UserAuthenticationOptions | false

  /**
   * The least secure storage the key may be stored in. With `strongBox` the key is stored in StrongBox, otherwise in
   * the default key storage of the device (see {@link KeyStorage}), which `trustedEnvironment` requires to be the TEE.
   * With `software` a key in software is accepted as well, which on most devices is still stored in the TEE.
   *
   * Generating a key throws a `SecureEnvironmentNotSupportedError` when the device doesn't support this storage, check
   * it first with `isSecureEnvironmentSupported`.
   *
   * @default 'strongBox'
   * @platform android
   */
  minimumKeyStorage?: KeyStorage

  /**
   * Creates a key attestation that includes this challenge, for example a nonce from the party that verifies the
   * attestation. Get it with `getAttestationCertificateChain`. Android allows at most 128 bytes.
   *
   * iOS has no key attestation for Secure Enclave keys, there the challenge is ignored.
   *
   * @platform android
   */
  attestationChallenge?: Uint8Array
}

/**
 * The texts of the prompt where the user authenticates.
 */
export interface AuthenticationPrompt {
  /**
   * The title of the prompt. On iOS this is the reason for the authentication. It shows in the Touch ID prompt and
   * on the passcode screen, but not in the Face ID prompt.
   *
   * @default 'Authenticate to sign data'
   */
  title?: string

  /**
   * Shown below the title.
   *
   * @platform android
   */
  subtitle?: string

  /**
   * The label of the cancel button. Android has no cancel button when the device credential is allowed; it shows a
   * button to use the device credential instead.
   *
   * @default 'Cancel'
   */
  cancel?: string
}

export interface SignOptions {
  /**
   * The prompt shown when the key requires user authentication.
   */
  prompt?: AuthenticationPrompt
}

/**
 * The authentication that `withUserAuthentication` passes to its callback.
 */
export interface UserAuthenticationSession {
  /**
   * Signs like `sign`, but reuses the authentication of `withUserAuthentication` instead of asking the user again.
   * Throws when called after the callback returned.
   */
  sign(keyId: string, message: Uint8Array, options?: SignOptions): Promise<Uint8Array>
}

export interface WithUserAuthenticationOptions {
  /**
   * The ways the user can authenticate. Keys that need a method that's not allowed here ask the user to
   * authenticate again, so use the same methods as the keys you sign with.
   *
   * @default ['biometric']
   */
  methods?: [UserAuthenticationMethod, ...UserAuthenticationMethod[]]

  /**
   * The prompt shown to authenticate.
   */
  prompt?: AuthenticationPrompt
}

/**
 * Where an existing Android key is stored: a {@link KeyStorage}, or `secureHardware` when Android only tells that the
 * key is in secure hardware, not whether that's StrongBox or the TEE. Android 11 always does this.
 */
export type StoredKeyStorage = KeyStorage | 'secureHardware'

export interface IsUserAuthenticationAvailableOptions {
  /**
   * The ways the user should be able to authenticate. With both, either one is enough.
   *
   * @default ['biometric']
   */
  methods?: [UserAuthenticationMethod, ...UserAuthenticationMethod[]]
}

export interface IsSecureEnvironmentSupportedOptions {
  /**
   * The minimum key storage to check, see `minimumKeyStorage` of {@link GenerateKeypairOptions}. With `software` the
   * device is always supported.
   *
   * @default 'strongBox'
   * @platform android
   */
  minimumKeyStorage?: KeyStorage
}
