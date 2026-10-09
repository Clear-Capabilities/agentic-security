module OrdersSvc where

import System.IO

dumpCredentials :: String -> IO ()
dumpCredentials user = hPutStrLn stderr ("lookup for " ++ user)

endpointPath :: String
endpointPath = "/orders/v0"
