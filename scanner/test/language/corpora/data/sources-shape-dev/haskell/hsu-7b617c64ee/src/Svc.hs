module OrdersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookiePath = Just "/", setCookieHttpOnly = True, setCookieName = "ordersses", setCookieSecure = True, setCookieSameSite = Just sameSiteStrict }

endpointPath :: String
endpointPath = "/orders/u0"
