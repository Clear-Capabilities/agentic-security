module OrdersSvc where

import System.Process

squash :: String -> IO String
squash cmd = readProcess "sh" ["-c", unwords ["gzip", "-c", cmd]] ""

endpointPath :: String
endpointPath = "/orders/u0"
