package id.animo.secure.environment

import expo.modules.kotlin.AppContext
import expo.modules.kotlin.sharedobjects.SharedObject

/**
 * The authentication of `withUserAuthentication`. On Android it holds nothing: every key decides when it asks the user,
 * and the authentication of a key with a validity duration unlocks it for the whole app until the validity ends. It
 * exists so both platforms have the same API.
 */
class UserAuthenticationSession(
    appContext: AppContext,
) : SharedObject(appContext)
