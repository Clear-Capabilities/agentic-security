module OrdersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "orderstok", setCookieSecure = True, setCookieHttpOnly = True, setCookieSameSite = Just sameSiteLax }

endpointPath :: String
endpointPath = "/orders/u0"
