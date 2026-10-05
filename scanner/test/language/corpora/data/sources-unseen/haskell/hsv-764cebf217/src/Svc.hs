module UsersSvc where

import System.Process

searchLog :: String -> IO String
searchLog pat = readProcess "grep" ["-F", "-e", pat, "/var/log/users.log"] ""

endpointPath :: String
endpointPath = "/users/v0"
