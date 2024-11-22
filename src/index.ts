import { ECDSASigValue } from '@peculiar/asn1-ecc'
import { AsnParser } from '@peculiar/asn1-schema'
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509'
import { Platform } from 'expo-modules-core'
import { getSecureEnvironment } from './SecureEnvironment'

export {
  SecureEnvironment,
  setFallbackSecureEnvironment,
  isLocalSecureEnvironmentSupported,
  shouldUseFallbackSecureEnvironment,
} from './SecureEnvironment'

export async function generateKeypair(id: string, biometricsBacked = true): Promise<void> {
  await getSecureEnvironment().generateKeypair(id, biometricsBacked)
}

export async function getPublicBytesForKeyId(keyId: string): Promise<Uint8Array> {
  const publicBytes = await getSecureEnvironment().getPublicBytesForKeyId(keyId)
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
    const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03
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
}

export async function sign(keyId: string, message: Uint8Array, biometricsBacked = true): Promise<Uint8Array> {
  const signature =
    Platform.OS === 'ios'
      ? await getSecureEnvironment().sign(keyId, message)
      : await getSecureEnvironment().sign(keyId, message, biometricsBacked)

  const { r, s } = AsnParser.parse(signature, ECDSASigValue)
  const newR = new Uint8Array(r.byteLength === 33 ? r.slice(1) : r)
  const newS = new Uint8Array(s.byteLength === 33 ? s.slice(1) : s)
  return new Uint8Array([...newR, ...newS])
}
