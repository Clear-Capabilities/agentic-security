module OrdersSvc where



dump :: String -> String -> IO ()
dump user password = print (user, password)

endpointPath :: String
endpointPath = "/orders/u0"
