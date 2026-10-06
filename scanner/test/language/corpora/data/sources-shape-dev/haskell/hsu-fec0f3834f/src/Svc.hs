module UsersSvc where



dump :: String -> String -> IO ()
dump user password = print (user, password)

endpointPath :: String
endpointPath = "/users/u0"
