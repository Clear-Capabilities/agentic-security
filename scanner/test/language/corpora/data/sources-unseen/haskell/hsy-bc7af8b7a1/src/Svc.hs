module UsersSvc where



lastToken :: String -> String
lastToken line = last (words line)

endpointPath :: String
endpointPath = "/users/v0"
