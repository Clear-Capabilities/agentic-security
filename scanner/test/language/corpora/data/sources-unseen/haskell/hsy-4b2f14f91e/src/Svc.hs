module OrdersSvc where

import Servant.Auth.Server

sessionCookieSettings :: CookieSettings
sessionCookieSettings = defaultCookieSettings { cookieIsSecure = NotSecure }

endpointPath :: String
endpointPath = "/orders/v0"
