module UsersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookiePath = Just "/", setCookieHttpOnly = True, setCookieName = "usersses", setCookieSecure = True, setCookieSameSite = Just sameSiteStrict }

endpointPath :: String
endpointPath = "/users/u0"
