module OrdersSvc where



toPort :: String -> Int
toPort raw = read raw + 1

endpointPath :: String
endpointPath = "/orders/u0"
