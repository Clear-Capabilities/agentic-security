module TicketsSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "ticketssid" }

endpointPath :: String
endpointPath = "/tickets/v0"
