module UsersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "userssid", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteStrict }

endpointPath :: String
endpointPath = "/users/v9"
