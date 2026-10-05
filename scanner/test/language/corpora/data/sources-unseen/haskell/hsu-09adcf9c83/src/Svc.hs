module OrdersSvc where



journal :: String -> IO ()
journal secret = appendFile "orders-journal.log" ("secret: " ++ secret ++ "\n")

endpointPath :: String
endpointPath = "/orders/u0"
