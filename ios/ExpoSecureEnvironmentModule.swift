import ExpoModulesCore

public class ExpoSecureEnvironmentModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoSecureEnvironment")

    Function("generateKeypair") { (id: String, biometricsBacked: Bool) -> Void in
      try SecureEnvironment.generateKeyPair(id, biometricsBacked)
    }

    Function("getPublicBytesForKeyId") { (keyId: String) -> Data in
      return try SecureEnvironment.getPublicBytesForKeyId(keyId)
    }

    AsyncFunction("sign") {
      (id: String, message: Data) async throws -> Data in
      return try await SecureEnvironment.sign(id, message)
    }
  }
}
