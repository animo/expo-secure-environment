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
  withUserAuthentication,
} from '@animo-id/expo-secure-environment'
import { Key, KeyAlgorithm } from '@openwallet-foundation/askar-react-native'
import * as Device from 'expo-device'
import { Platform } from 'react-native'
import { afterEach, describe, expect, test } from 'react-native-harness'

const isAndroid = Platform.OS === 'android'
// Below Android 11 apps can include the library, but can't use it
const isOldAndroid = isAndroid && (Platform.Version as number) < 30

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
  trustedEnvironment: ['strongBox', 'trustedEnvironment', 'secureHardware'],
  software: ['strongBox', 'trustedEnvironment', 'secureHardware', 'software'],
}

const describeIfPhysicalDevice = isPhysicalDevice && !isOldAndroid ? describe : describe.skip

describeIfPhysicalDevice('secure hardware on physical devices', () => {
  test(isAndroid ? 'has a TEE' : 'has a Secure Enclave', () => {
    expect(isSecureEnvironmentSupported({ minimumKeyStorage: 'trustedEnvironment' })).toBe(true)
  })
})

const describeIfOldAndroid = isOldAndroid ? describe : describe.skip

describeIfOldAndroid('below Android 11', () => {
  test('supports no key storage and no user authentication', () => {
    for (const keyStorage of ['strongBox', 'trustedEnvironment', 'software'] as const) {
      expect(isSecureEnvironmentSupported({ minimumKeyStorage: keyStorage })).toBe(false)
    }
    expect(isUserAuthenticationAvailable({ methods: ['biometric', 'deviceCredential'] })).toBe(false)
  })

  test('throws a SecureEnvironmentNotSupportedError from the functions that use keys', async () => {
    const keyId = newKeyId()
    const operations = [
      () => generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage: 'software' }),
      () => getPublicBytesForKeyId(keyId),
      () => getKeyStorage(keyId),
      () => getAttestationCertificateChain(keyId),
      () => sign(keyId, message),
      () => withUserAuthentication(async () => undefined),
      () => deleteKey(keyId),
    ]
    for (const operation of operations) {
      await expect(operation()).rejects.toBeInstanceOf(SecureEnvironmentNotSupportedError)
    }
  })
})

const describeIfNotOldAndroid = isOldAndroid ? describe.skip : describe

describeIfNotOldAndroid('errors', () => {
  test('have the native reason as message, without the native exception', async () => {
    const keyId = newKeyId()
    // A sync and an async native function
    for (const operation of [() => deleteKey(keyId), () => sign(keyId, message)]) {
      const error = await operation().then(
        () => undefined,
        (error: unknown) => error
      )
      expect(error).toBeInstanceOf(KeyNotFoundError)
      expect((error as KeyNotFoundError).message).toBe(`Key '${keyId}' not found`)
    }
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

    if (!isOldAndroid) {
      test('is always true for software', () => {
        expect(isSecureEnvironmentSupported({ minimumKeyStorage: 'software' })).toBe(true)
      })
    }
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

  test('signs with withUserAuthentication without asking for keys without user authentication', async () => {
    const sessionKeyIds = [newKeyId(), newKeyId()]
    for (const keyId of sessionKeyIds) await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })

    const { session, signatures } = await withUserAuthentication(async (session) => ({
      session,
      signatures: await Promise.all(sessionKeyIds.map((keyId) => session.sign(keyId, message))),
    }))

    for (const [index, keyId] of sessionKeyIds.entries()) {
      expect(await verify(keyId, message, signatures[index])).toBe(true)
    }
    await expect(session.sign(sessionKeyIds[0], message)).rejects.toBeInstanceOf(SecureEnvironmentError)
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

const hasStrongBox = isAndroid && isSecureEnvironmentSupported({ minimumKeyStorage: 'strongBox' })

describeIfAndroid('StrongBox preference', () => {
  test(
    hasStrongBox ? 'stores keys in StrongBox by default' : 'stores keys outside StrongBox without StrongBox',
    async () => {
      const keyId = newKeyId()
      await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage })

      const keyStorage = await getKeyStorage(keyId)
      if (hasStrongBox) {
        expect(allowedKeyStorages.strongBox).toContain(keyStorage)
      } else {
        expect(keyStorage).not.toBe('strongBox')
      }
    }
  )

  test('stores keys in the default key storage without preferStrongBox', async () => {
    const keyId = newKeyId()
    await generateKeypair(keyId, { userAuthentication: false, minimumKeyStorage, preferStrongBox: false })

    const keyStorage = await getKeyStorage(keyId)
    expect(allowedKeyStorages[minimumKeyStorage]).toContain(keyStorage)
    expect(keyStorage).not.toBe('strongBox')
  })
})

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
