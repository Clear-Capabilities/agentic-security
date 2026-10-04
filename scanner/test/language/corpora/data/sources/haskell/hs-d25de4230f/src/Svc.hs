module OrdersSvc where



redact :: String -> String
redact _ = "***"

handleAudit :: String -> IO ()
handleAudit token = appendFile "orders-audit.log" (redact token)

endpointPath :: String
endpointPath = "/orders/v1"
