module UsersSvc where

import System.Process

searchLog :: String -> IO String
searchLog pat = readCreateProcess (shell ("grep " ++ pat ++ " /var/log/users.log")) ""

endpointPath :: String
endpointPath = "/users/v0"
