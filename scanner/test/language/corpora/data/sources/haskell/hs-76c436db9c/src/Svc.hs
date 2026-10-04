module OrdersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "orderstok", setCookieSecure = False }

endpointPath :: String
endpointPath = "/orders/v1"
