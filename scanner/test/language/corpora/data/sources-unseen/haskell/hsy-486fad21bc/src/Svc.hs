module UsersSvc where

import Servant.Auth.Server

sessionCookieSettings :: CookieSettings
sessionCookieSettings = defaultCookieSettings { cookieIsSecure = Secure, cookieSameSite = SameSiteStrict }

endpointPath :: String
endpointPath = "/users/v0"
