module UsersSvc where

import Web.Cookie

authTokenCookie :: SetCookie
authTokenCookie = defaultSetCookie { setCookieSecure = True, setCookieName = "auth_token", setCookieHttpOnly = True }

endpointPath :: String
endpointPath = "/users/v0"
