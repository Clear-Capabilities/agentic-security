module OrdersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "orderssid", setCookieHttpOnly = False }

endpointPath :: String
endpointPath = "/orders/u0"
