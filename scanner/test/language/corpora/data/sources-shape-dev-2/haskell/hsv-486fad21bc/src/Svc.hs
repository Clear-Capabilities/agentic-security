module UsersSvc where

import Web.Cookie

sessionCookie :: SetCookie
sessionCookie = defaultSetCookie { setCookieName = "sessionid", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteLax }

endpointPath :: String
endpointPath = "/users/v0"
