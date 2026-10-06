module UsersSvc where



parseCount :: String -> Int
parseCount s = read s

endpointPath :: String
endpointPath = "/users/v0"
