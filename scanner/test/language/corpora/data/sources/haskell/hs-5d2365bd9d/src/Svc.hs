module OrdersSvc where



handleAudit :: String -> IO ()
handleAudit token = appendFile "orders-audit.log" token

endpointPath :: String
endpointPath = "/orders/v0"
