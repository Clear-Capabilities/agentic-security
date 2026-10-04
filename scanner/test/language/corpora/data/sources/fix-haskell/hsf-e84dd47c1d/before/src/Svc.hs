module UsersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "userssid" }

endpointPath :: String
endpointPath = "/users/v7"
