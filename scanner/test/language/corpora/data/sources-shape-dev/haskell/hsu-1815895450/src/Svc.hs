module UsersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "userstok", setCookieSecure = True, setCookieHttpOnly = True, setCookieSameSite = Just sameSiteLax }

endpointPath :: String
endpointPath = "/users/u0"
