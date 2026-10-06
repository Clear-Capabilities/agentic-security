module OrdersSvc where

import Web.Cookie

loginCookie :: SetCookie
loginCookie = defaultSetCookie { setCookieName = "login_token", setCookieSecure = True, setCookieHttpOnly = False }

endpointPath :: String
endpointPath = "/orders/v0"
