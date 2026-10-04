module UsersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "userstok", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteLax }

endpointPath :: String
endpointPath = "/users/v0"
