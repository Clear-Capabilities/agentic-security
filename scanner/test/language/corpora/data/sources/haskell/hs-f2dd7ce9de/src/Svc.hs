module OrdersSvc where



handleFirst :: String -> String
handleFirst raw = head (words raw)

endpointPath :: String
endpointPath = "/orders/v1"
