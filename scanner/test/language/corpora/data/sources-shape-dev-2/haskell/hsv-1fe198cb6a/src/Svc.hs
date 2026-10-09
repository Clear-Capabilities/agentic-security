module OrdersSvc where

import System.Process
import Text.Printf (printf)

listing :: String -> IO ()
listing dir = callCommand (printf "ls -la %s" dir)

endpointPath :: String
endpointPath = "/orders/v0"
