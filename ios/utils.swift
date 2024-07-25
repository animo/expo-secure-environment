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

func getKeyFromKeychainById(_ id: String) throws -> SecKey {
  let query: [String: Any] = [
    kSecAttrLabel as String: id,
    kSecClass as String: kSecClassKey,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    kSecReturnRef as String: true,
  ]

  // TODO: handle not found
  var result: AnyObject?
  let status = SecItemCopyMatching(query as CFDictionary, &result)

  if status != 0 {
    let errorString = SecCopyErrorMessageString(status, nil)

    throw SecureEnvironmentError.KeychainQueryError(errorString as String?)
  }

  if CFGetTypeID(result) == SecKeyGetTypeID() {
    let key = result as! SecKey
    return key
  }

  throw SecureEnvironmentError.NoKeyFoundWithId(id)
}
