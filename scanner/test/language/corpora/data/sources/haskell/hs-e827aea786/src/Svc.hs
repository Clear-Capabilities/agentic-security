module OrdersSvc where

import Data.Time.Clock.POSIX

handleNonce :: IO String
handleNonce = fmap show getPOSIXTime

endpointPath :: String
endpointPath = "/orders/v1"
