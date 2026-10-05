module UsersSvc where

import System.Process

squash :: String -> IO String
squash file = readProcess "gzip" ["-c", "--", file] ""

endpointPath :: String
endpointPath = "/users/u0"
