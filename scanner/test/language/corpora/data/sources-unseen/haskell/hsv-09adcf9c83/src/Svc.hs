module OrdersSvc where

import System.IO

dumpCredentials :: String -> IO ()
dumpCredentials token = hPrint stderr token

endpointPath :: String
endpointPath = "/orders/v0"
