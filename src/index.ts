import { ECDSASigValue } from '@peculiar/asn1-ecc'
import { AsnParser } from '@peculiar/asn1-schema'
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509'
import { Platform } from 'expo-modules-core'
import { getSecureEnvironment } from './SecureEnvironment'

export { SecureEnvironment, setFallbackSecureEnvironment } from './SecureEnvironment'

export function generateKeypair(id: string, biometricsBacked = true) {
  getSecureEnvironment().generateKeypair(id, biometricsBacked)
}

export function getPublicBytesForKeyId(keyId: string): Uint8Array {
  const publicBytes = getSecureEnvironment().getPublicBytesForKeyId(keyId)

  if (Platform.OS === 'android') {
    const spki = AsnParser.parse(publicBytes, SubjectPublicKeyInfo)
    const uncompressedKey = new Uint8Array(spki.subjectPublicKey)
    if (uncompressedKey.length !== 65 || uncompressedKey[0] !== 0x04) {
      throw new Error('Invalid uncompressed key format')
    }

    // Extract the X and Y coordinates
    const x = uncompressedKey.slice(1, 33) // bytes 1 to 32 (X coordinate)
    const y = uncompressedKey.slice(33, 65) // bytes 33 to 64 (Y coordinate)

    // Determine the parity of the Y coordinate
    const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03

    // Return the compressed key (prefix + X coordinate)
    const compressedKey = new Uint8Array(33)
    compressedKey[0] = prefix
    compressedKey.set(x, 1)

    return compressedKey
  }

  return publicBytes
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
