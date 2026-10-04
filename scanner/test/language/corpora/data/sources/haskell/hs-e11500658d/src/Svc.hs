module TicketsSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "ticketssid", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteStrict }

endpointPath :: String
endpointPath = "/tickets/v0"
