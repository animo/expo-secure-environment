import CryptoKit
import Foundation
import LocalAuthentication
import Security

struct SecureEnvironment {
  static func isSecureEnvironmentSupported() -> Bool {
    return SecureEnclave.isAvailable
  }

  static func generateKeyPair(_ keyId: String, _ options: GenerateKeypairOptions) throws {
    guard isSecureEnvironmentSupported() else {
      throw SecureEnvironmentNotSupportedException()
    }
    try assertKeyDoesNotExist(keyId)

    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if let userAuthentication = options.userAuthentication {
      let methods = userAuthentication.methods
      try assertUserAuthenticationAvailable(methods)

      switch (methods.contains(.biometric), methods.contains(.deviceCredential)) {
      case (true, true):
        // Like on Android, biometric changes don't invalidate the key when the passcode can unlock it anyway
        flags.formUnion([.biometryAny, .or, .devicePasscode])
      case (true, false):
        flags.formUnion(userAuthentication.invalidateOnBiometricChange ? .biometryCurrentSet : .biometryAny)
      case (false, true):
        flags.formUnion(.devicePasscode)
      case (false, false):
        throw SecureEnvironmentException("At least one user authentication method is required")
      }
    }

    var error: Unmanaged<CFError>?
    guard
      let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &error
      )
    else {
      let accessControlError = error!.takeRetainedValue() as Error
      throw SecureEnvironmentException("Could not create the access control: \(accessControlError.localizedDescription)")
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeEC,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecAttrLabel as String: keyId,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String:
        [
          kSecAttrIsPermanent as String: true,
          kSecAttrApplicationTag as String: Bundle.main.bundleIdentifier.unsafelyUnwrapped,
        ],
      kSecAttrAccessControl as String: accessControl,
    ]

    guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
      let generateError = error!.takeRetainedValue() as Error
      // The Secure Enclave can't protect the key with the requested authentication, e.g. the simulator without a
      // passcode, even though LocalAuthentication said the user can authenticate
      if options.userAuthentication != nil && (generateError as NSError).code == Int(errSecAuthFailed) {
        throw UserAuthenticationUnavailableException(
          "Could not generate key '\(keyId)' with the requested user authentication: \(generateError.localizedDescription)"
        )
      }
      throw SecureEnvironmentException("Could not generate key '\(keyId)': \(generateError.localizedDescription)")
    }
  }

  static func getPublicBytesForKeyId(_ keyId: String) throws -> Data {
    let key = try assertKeyExists(keyId)
    let publicKey = SecKeyCopyPublicKey(key)

    guard let pk = publicKey, publicKey != nil else {
      throw SecureEnvironmentException("Could not get the public key of key '\(keyId)'")
    }
    let extRep = SecKeyCopyExternalRepresentation(pk, nil)
    guard let er = extRep, extRep != nil else {
      throw SecureEnvironmentException("Could not get the public key of key '\(keyId)'")
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

  static func sign(
    _ keyId: String, _ message: Data, _ prompt: AuthenticationPrompt, _ session: UserAuthenticationSession?
  ) async throws -> Data {
    // The key asks the user to authenticate when it requires it, unless the context of the session already did
    let context = try session?.authenticatedContext() ?? createAuthenticationContext(prompt)
    let key = try assertKeyExists(keyId, context)

    var error: Unmanaged<CFError>?
    guard
      let signature = SecKeyCreateSignature(
        key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error)
    else {
      let signError = error!.takeRetainedValue() as Error
      throw toUserAuthenticationException(signError)
        ?? SecureEnvironmentException("Could not sign with key '\(keyId)': \(signError.localizedDescription)")
    }

    return signature as Data
  }

  // Authenticates the user once for the sign calls that get the returned session, they bind its authenticated
  // context to the keys
  static func authenticate(
    _ methods: [UserAuthenticationMethod], _ prompt: AuthenticationPrompt
  ) async throws -> UserAuthenticationSession {
    let context = createAuthenticationContext(prompt)
    let policy = authenticationPolicy(methods)
    if !methods.contains(.deviceCredential) {
      // Hides the button to use the passcode instead, it doesn't unlock keys that require biometrics
      context.localizedFallbackTitle = ""
    }

    try assertUserAuthenticationAvailable(methods)
    do {
      _ = try await context.evaluatePolicy(policy, localizedReason: prompt.title)
    } catch {
      if let exception = toUserAuthenticationException(error) {
        throw exception
      }
      throw error
    }

    return UserAuthenticationSession(context)
  }

  static func deleteKey(_ keyId: String) throws {
    let _ = try assertKeyExists(keyId)

    let query: [String: Any] = [
      kSecAttrLabel as String: keyId,
      kSecClass as String: kSecClassKey,
      kSecAttrKeyType as String: kSecAttrKeyTypeEC,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    ]

    SecItemDelete(query as CFDictionary)

    try assertKeyDoesNotExist(keyId)
  }

  private static func createAuthenticationContext(_ prompt: AuthenticationPrompt) -> LAContext {
    let context = LAContext()
    context.localizedReason = prompt.title
    context.localizedCancelTitle = prompt.cancel
    return context
  }

  private static func authenticationPolicy(_ methods: [UserAuthenticationMethod]) -> LAPolicy {
    return methods.contains(.deviceCredential)
      ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics
  }

  static func isUserAuthenticationAvailable(_ methods: [UserAuthenticationMethod]) -> Bool {
    return LAContext().canEvaluatePolicy(authenticationPolicy(methods), error: nil)
  }

  private static func assertUserAuthenticationAvailable(_ methods: [UserAuthenticationMethod]) throws {
    var error: NSError?
    guard LAContext().canEvaluatePolicy(authenticationPolicy(methods), error: &error) else {
      throw error.flatMap { toUserAuthenticationException($0) }
        ?? UserAuthenticationUnavailableException("The user can't authenticate with the requested methods")
    }
  }
}
