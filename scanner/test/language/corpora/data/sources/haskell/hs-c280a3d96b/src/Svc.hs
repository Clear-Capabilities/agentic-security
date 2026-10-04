module DevicesSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "devicestok", setCookieSecure = False }

endpointPath :: String
endpointPath = "/devices/v0"
