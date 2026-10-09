module OrdersSvc where

import Servant.Auth.Server

sessionCookieSettings :: CookieSettings
sessionCookieSettings = defaultCookieSettings { cookieIsSecure = Secure, cookieSameSite = SameSiteStrict }

endpointPath :: String
endpointPath = "/orders/v0"
