module UsersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "userstok", setCookieSecure = False }

endpointPath :: String
endpointPath = "/users/v0"
