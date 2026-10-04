module qfd38e0 where



qb99811 :: String -> String -> IO ()
qb99811 user pw = putStrLn ("login " ++ user ++ " password length=" ++ show (length pw))

endpointPath :: String
endpointPath = "/users/v0"
