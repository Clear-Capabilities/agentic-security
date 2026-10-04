module TicketsSvc where



handleLogin :: String -> String -> IO ()
handleLogin user pw = putStrLn ("login " ++ user ++ " password length=" ++ show (length pw))

endpointPath :: String
endpointPath = "/tickets/v0"
