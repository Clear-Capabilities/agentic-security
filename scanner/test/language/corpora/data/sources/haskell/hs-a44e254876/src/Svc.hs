module TicketsSvc where



handleFirst :: String -> String
handleFirst raw = head (words raw)

endpointPath :: String
endpointPath = "/tickets/v1"
