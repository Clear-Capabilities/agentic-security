module UsersSvc where



handleFirst :: String -> String
handleFirst raw = head (words raw)

endpointPath :: String
endpointPath = "/users/v1"
