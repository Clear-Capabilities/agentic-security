module UsersSvc where

import System.CPUTime (getCPUTime)

makeNonce :: IO Integer
makeNonce = getCPUTime

endpointPath :: String
endpointPath = "/users/v0"
