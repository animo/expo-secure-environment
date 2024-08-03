import Foundation
import LocalAuthentication
import Security

struct SecureEnvironment {
  static func generateKeyPair(_ keyId: String, _ biometricsBacked: Bool) throws {
    var attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeEC,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecAttrLabel as String: keyId,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String:
        [
          kSecAttrIsPermanent as String: true,
          kSecAttrApplicationTag as String: Bundle.main.bundleIdentifier.unsafelyUnwrapped,
        ],
    ]

    if biometricsBacked {
      let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        nil
      )

      attributes[kSecAttrAccessControl as String] = accessControl
    }

    var error: Unmanaged<CFError>?
    guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
      throw error!.takeRetainedValue() as Error
    }
  }

  static func getPublicBytesForKeyId(_ keyId: String) throws -> Data {
    let key = try getKeyFromKeychainById(keyId)
    let publicKey = SecKeyCopyPublicKey(key)
    guard let pk = publicKey, publicKey != nil else {
      throw SecureEnvironmentError.CouldNotConvertIntoPublicKey
    }
    let extRep = SecKeyCopyExternalRepresentation(pk, nil)
    guard let er = extRep, extRep != nil else {
      throw SecureEnvironmentError.CouldNotConvertIntoExternalRepresentation
    }
    let length = CFDataGetLength(er)
    var data = Data(count: length)
    data.withUnsafeMutableBytes { (bytes: UnsafeMutableRawBufferPointer) in
      if let baseAddress = bytes.baseAddress {
        CFDataGetBytes(
          extRep, CFRange(location: 0, length: length),
          baseAddress.assumingMemoryBound(to: UInt8.self))
      }
    }
    return compressPublicKey(data)
  }

  static func sign(_ keyId: String, _ message: Data) async throws -> Data
  {
    let key = try getKeyFromKeychainById(keyId)
    var error: Unmanaged<CFError>?
    guard
      let signature = SecKeyCreateSignature(
        key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error)
    else {
      throw error!.takeRetainedValue() as Error
    }

    return signature as Data
  }
}
