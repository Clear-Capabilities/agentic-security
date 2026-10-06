module OrdersSvc where

import System.Process

listing :: String -> IO ()
listing dir = callProcess "ls" ["-la", "--", dir]

endpointPath :: String
endpointPath = "/orders/v0"
