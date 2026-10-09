module OrdersSvc where

import Web.Cookie

authTokenCookie :: SetCookie
authTokenCookie = defaultSetCookie { setCookieName = "auth_token", setCookieSecure = False, setCookieHttpOnly = True }

endpointPath :: String
endpointPath = "/orders/v0"
