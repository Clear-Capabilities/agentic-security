module DevicesSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "devicessid", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteStrict }

endpointPath :: String
endpointPath = "/devices/v1"
