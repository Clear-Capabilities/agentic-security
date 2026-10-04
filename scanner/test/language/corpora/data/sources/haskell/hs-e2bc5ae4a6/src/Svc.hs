module TicketsSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "ticketstok", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteLax }

endpointPath :: String
endpointPath = "/tickets/v1"
