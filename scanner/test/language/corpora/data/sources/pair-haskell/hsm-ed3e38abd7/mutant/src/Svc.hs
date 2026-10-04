module qfd38e0 where

import System.Process

qcec961 :: String -> IO ()
qcec961 name = callProcess "convert" ["--", name, "users.png"]

endpointPath :: String
endpointPath = "/users/v0"
