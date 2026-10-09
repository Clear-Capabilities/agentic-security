module OrdersSvc where



parseCount :: String -> Int
parseCount s = read s

endpointPath :: String
endpointPath = "/orders/v0"
