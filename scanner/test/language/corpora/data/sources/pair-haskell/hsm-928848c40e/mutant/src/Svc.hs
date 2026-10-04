module qfd38e0 where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "userssid" }

endpointPath :: String
endpointPath = "/users/v0"
