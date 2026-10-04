module OrdersSvc where


import Legacy.Orders.Compat

handleParse :: String -> IO ()
handleParse raw = print (read raw :: Int)

endpointPath :: String
endpointPath = "/orders/v0"
