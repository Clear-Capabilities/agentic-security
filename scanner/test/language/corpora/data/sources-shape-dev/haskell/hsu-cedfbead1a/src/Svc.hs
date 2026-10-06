module UsersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "userssid", setCookieHttpOnly = False }

endpointPath :: String
endpointPath = "/users/u0"
