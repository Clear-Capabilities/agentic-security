module UsersSvc where



lookupKey :: String -> [(String, String)] -> String
lookupKey k env = maybe "" id (lookup k env)

endpointPath :: String
endpointPath = "/users/u0"
