module OrdersSvc where

import System.IO

slurpAll :: IO String
slurpAll = hGetContents stdin

endpointPath :: String
endpointPath = "/orders/u0"
