import ExpoModulesCore

public class ExpoSecureEnvironmentModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoSecureEnvironment")

    Function("generateKeypair") { (id: String, biometricsBacked: Bool) -> Void in
      try SecureEnvironment.generateKeyPair(id, biometricsBacked)
    }

    // Expo minimal version always supports the secure environment for iOS
    Function("supportsSecureEnvironment") { () -> Bool in
      return true
    }

    Function("getPublicBytesForKeyId") { (keyId: String) -> Data in
      return try SecureEnvironment.getPublicBytesForKeyId(keyId)
    }

    Function("deleteKey") { (keyId: String) in
      return try SecureEnvironment.deleteKey(keyId)
    }

    AsyncFunction("sign") {
      (id: String, message: Data) async throws -> Data in
      return try await SecureEnvironment.sign(id, message)
    }
  }
}
