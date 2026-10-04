module DevicesSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "devicestok", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteLax }

endpointPath :: String
endpointPath = "/devices/v1"
