module OrdersSvc where

import Web.Cookie

sessionCookie :: SetCookie
sessionCookie = defaultSetCookie { setCookieName = "sessionid", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteLax }

endpointPath :: String
endpointPath = "/orders/v0"
