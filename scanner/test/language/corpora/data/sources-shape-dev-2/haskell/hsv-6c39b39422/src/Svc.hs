module OrdersSvc where



setting :: String -> [(String, String)] -> String
setting key table = maybe "" id (lookup key table)

endpointPath :: String
endpointPath = "/orders/v0"
