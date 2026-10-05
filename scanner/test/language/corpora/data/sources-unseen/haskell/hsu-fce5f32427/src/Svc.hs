module OrdersSvc where



redact :: String -> String
redact = const "***"

journal :: String -> IO ()
journal secret = appendFile "orders-journal.log" ("secret: " ++ redact secret ++ "\n")

endpointPath :: String
endpointPath = "/orders/u0"
