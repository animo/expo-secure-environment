import ExpoModulesCore
import LocalAuthentication

// The authentication of `withUserAuthentication`. The first sign call with this session that needs user
// authentication authenticates its context, and the next ones reuse it. It ends when JavaScript releases the session.
final class UserAuthenticationSession: SharedObject, @unchecked Sendable {
  private let lock = NSLock()
  private var context: LAContext?

  init(_ context: LAContext) {
    self.context = context
    super.init()
  }

  func authenticationContext() throws -> LAContext {
    lock.lock()
    defer { lock.unlock() }
    guard let context else {
      throw SecureEnvironmentException("The user authentication has ended")
    }
    return context
  }

  override func sharedObjectWillRelease() {
    lock.lock()
    defer { lock.unlock() }
    // Sign calls that still use the context fail, instead of reusing the authentication
    context?.invalidate()
    context = nil
  }
}
