module OrdersSvc where



handleLogin :: String -> String -> IO ()
handleLogin user pw = putStrLn ("login " ++ user ++ " password length=" ++ show (length pw))

endpointPath :: String
endpointPath = "/orders/v0"
