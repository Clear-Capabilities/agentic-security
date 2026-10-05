module OrdersSvc where

import System.CPUTime (getCPUTime)

makeNonce :: IO Integer
makeNonce = getCPUTime

endpointPath :: String
endpointPath = "/orders/v0"
