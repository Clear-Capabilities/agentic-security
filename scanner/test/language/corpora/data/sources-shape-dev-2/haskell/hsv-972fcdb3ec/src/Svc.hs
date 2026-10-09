module OrdersSvc where

import Web.Cookie

sessionCookie :: SetCookie
sessionCookie = defaultSetCookie { setCookieName = "sessionid" }

endpointPath :: String
endpointPath = "/orders/v0"
