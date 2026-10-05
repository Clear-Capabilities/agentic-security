module OrdersSvc where

import Web.Cookie

themeCookie :: SetCookie
themeCookie = defaultSetCookie { setCookieName = "theme_preference" }

endpointPath :: String
endpointPath = "/orders/v0"
