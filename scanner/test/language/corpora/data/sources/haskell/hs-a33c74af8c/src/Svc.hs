module DevicesSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "devicessid" }

endpointPath :: String
endpointPath = "/devices/v0"
