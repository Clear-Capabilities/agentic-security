module UsersSvc where

import System.Process

announce :: String -> IO ()
announce msg = if msg `elem` ["start", "stop", "status"] then callCommand ("echo " ++ msg) else pure ()

endpointPath :: String
endpointPath = "/users/v0"
