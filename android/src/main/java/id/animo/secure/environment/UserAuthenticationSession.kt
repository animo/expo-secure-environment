package id.animo.secure.environment

import expo.modules.kotlin.AppContext
import expo.modules.kotlin.sharedobjects.SharedObject

/**
 * The authentication of `withUserAuthentication`. On Android it holds nothing: the authentication unlocks the keys
 * with a validity duration for the whole app until the validity ends. It exists so both platforms have the same API.
 */
class UserAuthenticationSession(
    appContext: AppContext,
) : SharedObject(appContext)
