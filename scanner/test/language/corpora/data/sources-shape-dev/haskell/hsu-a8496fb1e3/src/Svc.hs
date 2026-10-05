module UsersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "userstok", setCookieSameSite = Just sameSiteNone }

endpointPath :: String
endpointPath = "/users/u0"
