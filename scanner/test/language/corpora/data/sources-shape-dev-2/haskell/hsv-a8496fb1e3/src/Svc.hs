module UsersSvc where

import Web.Cookie

authTokenCookie :: SetCookie
authTokenCookie = defaultSetCookie { setCookieName = "auth_token", setCookieSecure = False, setCookieHttpOnly = True }

endpointPath :: String
endpointPath = "/users/v0"
