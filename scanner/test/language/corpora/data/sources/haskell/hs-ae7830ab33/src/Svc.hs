module OrdersSvc where



handleParse :: String -> IO ()
handleParse raw = print (read raw :: Int)

endpointPath :: String
endpointPath = "/orders/v1"
