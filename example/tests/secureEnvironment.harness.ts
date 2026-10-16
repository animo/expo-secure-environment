import {
  KeyAlreadyExistsError,
  KeyNotFoundError,
  type KeyStorage,
  SecureEnvironmentError,
  SecureEnvironmentNotSupportedError,
  type StoredKeyStorage,
  UserAuthenticationLockedOutError,
  type UserAuthenticationMethod,
  UserAuthenticationUnavailableError,
  deleteKey,
  generateKeypair,
  getAttestationCertificateChain,
  getKeyStorage,
  getPublicBytesForKeyId,
  isSecureEnvironmentSupported,
  isUserAuthenticationAvailable,
  sign,
} from '@animo-id/expo-secure-environment'
import { Key, KeyAlgorithm } from '@openwallet-foundation/askar-react-native'
import * as Device from 'expo-device'
import { Platform } from 'react-native'
import { afterEach, describe, expect, test } from 'react-native-harness'

const isAndroid = Platform.OS === 'android'

// Physical devices have secure hardware, so there the tests require it. Emulators often store keys in software and
// simulators may have no Secure Enclave, so there only the tests that work without secure hardware run. iOS ignores the
// key storage
const isPhysicalDevice = Device.isDevice
const minimumKeyStorage: KeyStorage = isPhysicalDevice ? 'trustedEnvironment' : 'software'
const isSupported = isSecureEnvironmentSupported({ minimumKeyStorage })

const message = new TextEncoder().encode('Hello from the expo-secure-environment tests')

let keyIds: string[] = []
const newKeyId = () => {
  const keyId = `harness-${Date.now()}-${keyIds.length}`
  keyIds.push(keyId)
  return keyId
}

afterEach(async () => {
  for (const keyId of keyIds) await deleteKey(keyId).catch(() => undefined)
  keyIds = []
})

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

const verify = async (keyId: string, data: Uint8Array, signature: Uint8Array) => {
  const publicKey = await getPublicBytesForKeyId(keyId)
  return Key.fromPublicBytes({ algorithm: KeyAlgorithm.EcSecp256r1, publicKey }).verifySignature({
    message: data,
    signature,
  })
}

// Where a key may end up for each minimum key storage. Android 11 reports `secureHardware` for StrongBox and TEE keys
const allowedKeyStorages: Record<KeyStorage, StoredKeyStorage[]> = {
  strongBox: ['strongBox', 'secureHardware'],
  trustedEnvironment: ['trustedEnvironment', 'secureHardware'],
  software: ['strongBox', 'trustedEnvironment', 'secureHardware', 'software'],
}

const describeIfPhysicalDevice = isPhysicalDevice ? describe : describe.skip

describeIfPhysicalDevice('secure hardware on physical devices', () => {
  test(isAndroid ? 'has a TEE' : 'has a Secure Enclave', () => {
    expect(isSecureEnvironmentSupported({ minimumKeyStorage: 'trustedEnvironment' })).toBe(true)
  })
})

describe('isSecureEnvironmentSupported', () => {
  if (isAndroid) {
    for (const keyStorage of ['strongBox', 'trustedEnvironment', 'software'] as const) {
      test(`matches key generation and signing with minimum key storage ${keyStorage}`, async () => {
        const keyId = newKeyId()
        const generate = generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage: keyStorage })

        if (!isSecureEnvironmentSupported({ minimumKeyStorage: keyStorage })) {
          await expect(generate).rejects.toBeInstanceOf(SecureEnvironmentNotSupportedError)
          return
        }

        await generate
        expect(allowedKeyStorages[keyStorage]).toContain(await getKeyStorage(keyId))
        expect(await verify(keyId, message, await sign(keyId, message))).toBe(true)
      })
    }

    test('is always true for software', () => {
      expect(isSecureEnvironmentSupported({ minimumKeyStorage: 'software' })).toBe(true)
    })
  } else {
    test('matches key generation in the Secure Enclave', async () => {
      const generate = generateKeypair(newKeyId(), { userAuthentication: false })

      if (isSupported) {
        await generate
      } else {
        await expect(generate).rejects.toBeInstanceOf(SecureEnvironmentNotSupportedError)
      }
    })
  }
})

const describeIfSupported = isSupported ? describe : describe.skip

describeIfSupported('keys', () => {
  test('generates a key and returns the compressed public key', async () => {
    const keyId = newKeyId()
    await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })

    const publicKey = await getPublicBytesForKeyId(keyId)
    expect(publicKey.length).toBe(33)
    expect([0x02, 0x03]).toContain(publicKey[0])
  })

  test('deletes a key', async () => {
    const keyId = newKeyId()
    await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })
    await deleteKey(keyId)

    await expect(getPublicBytesForKeyId(keyId)).rejects.toBeInstanceOf(KeyNotFoundError)
  })

  test('rejects a duplicate key id and keeps the existing key', async () => {
    const keyId = newKeyId()
    await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })
    const publicKey = await getPublicBytesForKeyId(keyId)

    await expect(generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })).rejects.toBeInstanceOf(
      KeyAlreadyExistsError
    )
    expect(toHex(await getPublicBytesForKeyId(keyId))).toBe(toHex(publicKey))
  })

  test('rejects deleting a missing key', async () => {
    const keyId = newKeyId()
    await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })
    await deleteKey(keyId)

    await expect(deleteKey(keyId)).rejects.toBeInstanceOf(KeyNotFoundError)
  })

  test('rejects signing with a missing key', async () => {
    await expect(sign(newKeyId(), message)).rejects.toBeInstanceOf(KeyNotFoundError)
  })

  test('signs without user authentication', async () => {
    const keyId = newKeyId()
    await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })

    const signature = await sign(keyId, message)
    expect(signature.length).toBe(64)
    expect(await verify(keyId, message, signature)).toBe(true)
    expect(await verify(keyId, new TextEncoder().encode('Another message'), signature)).toBe(false)
  })
})

describeIfSupported('user authentication', () => {
  const methodCases: [UserAuthenticationMethod, ...UserAuthenticationMethod[]][] = [
    ['biometric'],
    ['biometric', 'deviceCredential'],
  ]
  for (const methods of methodCases) {
    test(`isUserAuthenticationAvailable matches key generation with ${methods.join(' or ')}`, async () => {
      const error = await generateKeypair(newKeyId(), {
        userAuthentication: { methods },
        minimumKeyStorage,
      }).then(
        () => undefined,
        (error: unknown) => error
      )

      if (!isUserAuthenticationAvailable({ methods })) {
        expect(
          error instanceof UserAuthenticationUnavailableError || error instanceof UserAuthenticationLockedOutError
        ).toBe(true)
      } else if (!isAndroid && !isPhysicalDevice && methods.includes('deviceCredential')) {
        // The simulator reports the device passcode as available, but can't generate keys that require it
        expect(error === undefined || error instanceof UserAuthenticationUnavailableError).toBe(true)
      } else {
        expect(error).toBeUndefined()
      }
    })
  }
})

const describeIfAndroid = isAndroid ? describeIfSupported : describe.skip
const describeIfIos = isAndroid ? describe.skip : describe

describeIfAndroid('key attestation', () => {
  test('returns a certificate chain with the challenge', async () => {
    const keyId = newKeyId()
    const challenge = new TextEncoder().encode(`harness-challenge-${Date.now()}`)
    await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage, attestationChallenge: challenge })

    const chain = await getAttestationCertificateChain(keyId)
    expect(chain.length).toBeGreaterThanOrEqual(2)

    // The key description extension of the leaf certificate holds the challenge as is
    const leaf = Uint8Array.from(atob(chain[0] as string), (character) => character.charCodeAt(0))
    expect(toHex(leaf)).toContain(toHex(challenge))
  })
})

describeIfIos('Android only functions on iOS', () => {
  test('getKeyStorage throws', async () => {
    await expect(getKeyStorage('any-key')).rejects.toBeInstanceOf(SecureEnvironmentError)
  })

  test('getAttestationCertificateChain throws', async () => {
    await expect(getAttestationCertificateChain('any-key')).rejects.toBeInstanceOf(SecureEnvironmentError)
  })
})
