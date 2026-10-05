module OrdersSvc where

import System.Process

searchLog :: String -> IO String
searchLog pat = readCreateProcess (shell ("grep " ++ pat ++ " /var/log/orders.log")) ""

endpointPath :: String
endpointPath = "/orders/v0"
