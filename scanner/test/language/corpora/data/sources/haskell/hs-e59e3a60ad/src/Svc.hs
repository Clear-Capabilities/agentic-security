module TicketsSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "ticketstok", setCookieSecure = False }

endpointPath :: String
endpointPath = "/tickets/v0"
