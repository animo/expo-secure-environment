import Foundation

func compressPublicKey(_ publicKeyData: Data) -> Data {
  // P-256 public key raw representation is 65 bytes: 0x04 || X || Y
  assert(publicKeyData.count == 65, "Invalid public key length")

  let xCoord = publicKeyData[1...32]
  let yCoord = publicKeyData[33...64]

  // Determine the prefix byte based on the parity of the Y coordinate
  let prefix: UInt8 = yCoord.last! % 2 == 0 ? 0x02 : 0x03

  // The compressed form is: prefix || X
  var compressedKey = Data()
  compressedKey.append(prefix)
  compressedKey.append(contentsOf: xCoord)

  return compressedKey
}

func assertKeyExists(_ keyId: String) throws -> SecKey {
  let query: [String: Any] = [
    kSecAttrLabel as String: keyId,
    kSecClass as String: kSecClassKey,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    kSecReturnRef as String: true,
  ]

  var key: AnyObject?
  let status = SecItemCopyMatching(query as CFDictionary, &key)

  switch status {
  case errSecSuccess:
    if CFGetTypeID(key) != SecKeyGetTypeID() {
      throw SecureEnvironmentError.KeychainQueryError(keyId)
    }

    return key as! SecKey
  default:
    throw SecureEnvironmentError.KeyNotFound(keyId)
  }
}

func assertKeyDoesNotExist(_ keyId: String) throws {
  let query: [String: Any] = [
    kSecAttrLabel as String: keyId,
    kSecClass as String: kSecClassKey,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    kSecReturnRef as String: true,
  ]

  var result: AnyObject?
  let status = SecItemCopyMatching(query as CFDictionary, &result)

  switch status {
  case errSecItemNotFound:
    return
  default:
    throw SecureEnvironmentError.KeyAlreadyExists(keyId)
  }
}
