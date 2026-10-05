module OrdersSvc where



dump :: String -> String -> IO ()
dump user _ = print (user, "[redacted]" :: String)

endpointPath :: String
endpointPath = "/orders/u0"
