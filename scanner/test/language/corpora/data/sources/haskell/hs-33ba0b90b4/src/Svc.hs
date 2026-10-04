module OrdersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "orderssid" }

endpointPath :: String
endpointPath = "/orders/v0"
