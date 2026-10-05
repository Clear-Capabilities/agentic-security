module OrdersSvc where

import System.Process

squash :: String -> IO String
squash file = readProcess "gzip" ["-c", "--", file] ""

endpointPath :: String
endpointPath = "/orders/u0"
