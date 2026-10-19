import Foundation
import LocalAuthentication

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

// The returned key uses the `context` for user authentication, when given
func assertKeyExists(_ keyId: String, _ context: LAContext? = nil) throws -> SecKey {
  var query: [String: Any] = [
    kSecAttrLabel as String: keyId,
    kSecClass as String: kSecClassKey,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    kSecReturnRef as String: true,
  ]
  if let context = context {
    query[kSecUseAuthenticationContext as String] = context
  }

  var key: AnyObject?
  let status = SecItemCopyMatching(query as CFDictionary, &key)

  switch status {
  case errSecSuccess:
    if CFGetTypeID(key) != SecKeyGetTypeID() {
      throw SecureEnvironmentException("Keychain item for key '\(keyId)' is not a key")
    }

    return key as! SecKey
  case errSecItemNotFound:
    throw KeyNotFoundException(keyId)
  default:
    throw keychainException(status, "Could not read key '\(keyId)'")
  }
}

// Keeps the reason of other keychain errors, e.g. a missing entitlement when the app isn't signed
private func keychainException(_ status: OSStatus, _ message: String) -> SecureEnvironmentException {
  let reason = SecCopyErrorMessageString(status, nil) as String? ?? "unknown error"
  return SecureEnvironmentException("\(message): \(reason) (OSStatus \(status))")
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
  case errSecSuccess:
    throw KeyAlreadyExistsException(keyId)
  default:
    throw keychainException(status, "Could not check whether key '\(keyId)' exists")
  }
}
