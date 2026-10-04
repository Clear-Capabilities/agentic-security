module UsersSvc where



handleLogin :: String -> String -> IO ()
handleLogin user pw = putStrLn ("login " ++ user ++ " password=" ++ pw)

endpointPath :: String
endpointPath = "/users/v1"
