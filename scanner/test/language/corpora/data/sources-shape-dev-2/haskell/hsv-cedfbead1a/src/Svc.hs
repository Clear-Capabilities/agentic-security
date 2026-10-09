module UsersSvc where

import Web.Cookie

sessionCookie :: SetCookie
sessionCookie = defaultSetCookie { setCookieName = "sessionid" }

endpointPath :: String
endpointPath = "/users/v0"
