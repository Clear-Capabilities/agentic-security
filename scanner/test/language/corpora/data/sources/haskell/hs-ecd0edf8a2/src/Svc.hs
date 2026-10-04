module UsersSvc where


{-# LANGUAGE TemplateHaskell #-}
$(deriveJSON defaultOptions ''Users)

handleLogin :: String -> String -> IO ()
handleLogin user pw = putStrLn ("login " ++ user ++ " password=" ++ pw)

endpointPath :: String
endpointPath = "/users/v0"
