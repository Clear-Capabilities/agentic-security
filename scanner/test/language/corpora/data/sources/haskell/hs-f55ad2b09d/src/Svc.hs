module TicketsSvc where

import Web.Cookie
class Sink a where
  emitTickets :: a -> IO ()

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "ticketssid" }

endpointPath :: String
endpointPath = "/tickets/v0"
