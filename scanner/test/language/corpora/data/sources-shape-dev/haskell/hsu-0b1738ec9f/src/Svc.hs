module UsersSvc where

import System.Process

probe :: String -> IO ()
probe host = callProcess "ping" ["-c1", "--", host]

endpointPath :: String
endpointPath = "/users/u0"
