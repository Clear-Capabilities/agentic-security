module TicketsSvc where



redact :: String -> String
redact _ = "***"

handleAudit :: String -> IO ()
handleAudit token = appendFile "tickets-audit.log" (redact token)

endpointPath :: String
endpointPath = "/tickets/v0"
