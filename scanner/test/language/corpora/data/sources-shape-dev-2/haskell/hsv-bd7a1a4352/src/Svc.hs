module UsersSvc where

import Web.Cookie

themeCookie :: SetCookie
themeCookie = defaultSetCookie { setCookieName = "theme_preference" }

endpointPath :: String
endpointPath = "/users/v0"
