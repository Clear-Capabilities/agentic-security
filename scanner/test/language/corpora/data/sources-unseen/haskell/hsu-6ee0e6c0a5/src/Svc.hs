module OrdersSvc where



lookupKey :: String -> [(String, String)] -> String
lookupKey k env = maybe "" id (lookup k env)

endpointPath :: String
endpointPath = "/orders/u0"
