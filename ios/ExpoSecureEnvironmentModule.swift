import ExpoModulesCore

public class ExpoSecureEnvironmentModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoSecureEnvironment")

    // iOS always stores keys in the Secure Enclave, the key storage only applies to Android
    Function("isSecureEnvironmentSupported") { (_: String) -> Bool in
      return SecureEnvironment.isSecureEnvironmentSupported()
    }

    Function("isUserAuthenticationAvailable") { (methods: [UserAuthenticationMethod]) -> Bool in
      return SecureEnvironment.isUserAuthenticationAvailable(methods)
    }

    Function("generateKeypair") { (keyId: String, options: GenerateKeypairOptions) -> Void in
      try SecureEnvironment.generateKeyPair(keyId, options)
    }

    Function("getPublicBytesForKeyId") { (keyId: String) -> Data in
      return try SecureEnvironment.getPublicBytesForKeyId(keyId)
    }

    Function("deleteKey") { (keyId: String) in
      return try SecureEnvironment.deleteKey(keyId)
    }

    AsyncFunction("sign") {
      (keyId: String, message: Data, prompt: AuthenticationPrompt, session: UserAuthenticationSession?) async throws
        -> Data in
      return try await SecureEnvironment.sign(keyId, message, prompt, session)
    }

    Function("createUserAuthenticationSession") { (prompt: AuthenticationPrompt) -> UserAuthenticationSession in
      return SecureEnvironment.createUserAuthenticationSession(prompt)
    }

    // Created by `createUserAuthenticationSession`, JavaScript releases it when the authentication ends
    Class(UserAuthenticationSession.self) {}
  }
}
