module UsersSvc where

import Web.Cookie

loginCookie :: SetCookie
loginCookie = defaultSetCookie { setCookieName = "login_token", setCookieSecure = True, setCookieHttpOnly = False }

endpointPath :: String
endpointPath = "/users/v0"
