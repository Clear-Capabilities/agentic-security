module OrdersSvc where

import System.Process

searchLog :: String -> IO String
searchLog pat = readProcess "grep" ["-F", "-e", pat, "/var/log/orders.log"] ""

endpointPath :: String
endpointPath = "/orders/v0"
