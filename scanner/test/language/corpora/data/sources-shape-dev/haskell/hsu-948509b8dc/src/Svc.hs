module OrdersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "orderstok", setCookieSameSite = Just sameSiteNone }

endpointPath :: String
endpointPath = "/orders/u0"
