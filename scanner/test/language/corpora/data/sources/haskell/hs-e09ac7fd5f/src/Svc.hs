module TicketsSvc where



handleAudit :: String -> IO ()
handleAudit token = appendFile "tickets-audit.log" token

endpointPath :: String
endpointPath = "/tickets/v1"
