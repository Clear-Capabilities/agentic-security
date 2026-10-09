module UsersSvc where

import System.Process

runShell :: String -> IO ()
runShell cmd = callCommand cmd

compress :: String -> IO ()
compress target = runShell ("gzip -9 " ++ target)

endpointPath :: String
endpointPath = "/users/v0"
