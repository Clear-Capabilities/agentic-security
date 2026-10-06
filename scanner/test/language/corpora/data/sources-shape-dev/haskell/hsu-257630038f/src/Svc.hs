module OrdersSvc where

import System.Process

probe :: String -> IO ()
probe host = callProcess "ping" ["-c1", "--", host]

endpointPath :: String
endpointPath = "/orders/u0"
