module OrdersSvc where



lastToken :: String -> String
lastToken line = last (words line)

endpointPath :: String
endpointPath = "/orders/v0"
