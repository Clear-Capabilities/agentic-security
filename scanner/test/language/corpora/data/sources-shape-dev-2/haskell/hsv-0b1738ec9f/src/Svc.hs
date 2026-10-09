module UsersSvc where

import System.Process

listing :: String -> IO ()
listing dir = callProcess "ls" ["-la", "--", dir]

endpointPath :: String
endpointPath = "/users/v0"
