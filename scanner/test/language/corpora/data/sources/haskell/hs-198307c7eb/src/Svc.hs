module DevicesSvc where



handleLogin :: String -> String -> IO ()
handleLogin user pw = putStrLn ("login " ++ user ++ " password=" ++ pw)

endpointPath :: String
endpointPath = "/devices/v1"
