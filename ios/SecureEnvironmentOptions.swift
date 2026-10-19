import ExpoModulesCore

// The Android only options (key storage, attestation challenge and validity seconds) are left out

enum UserAuthenticationMethod: String, Enumerable {
  case biometric
  case deviceCredential
}

struct UserAuthenticationOptions: Record {
  @Field
  var methods: [UserAuthenticationMethod] = [.biometric]

  @Field
  var invalidateOnBiometricChange: Bool = true
}

struct GenerateKeypairOptions: Record {
  // Nil when signing doesn't require user authentication
  @Field
  var userAuthentication: UserAuthenticationOptions? = nil
}

struct AuthenticationPrompt: Record {
  @Field
  var title: String = "Authenticate to sign data"

  @Field
  var cancel: String = "Cancel"
}
