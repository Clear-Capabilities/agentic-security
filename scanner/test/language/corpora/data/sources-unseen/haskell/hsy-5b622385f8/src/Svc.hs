module UsersSvc where

import Servant.Auth.Server

sessionCookieSettings :: CookieSettings
sessionCookieSettings = defaultCookieSettings { cookieIsSecure = NotSecure }

endpointPath :: String
endpointPath = "/users/v0"
