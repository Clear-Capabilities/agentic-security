module UsersSvc where

import System.IO

slurpAll :: IO String
slurpAll = hGetContents stdin

endpointPath :: String
endpointPath = "/users/u0"
