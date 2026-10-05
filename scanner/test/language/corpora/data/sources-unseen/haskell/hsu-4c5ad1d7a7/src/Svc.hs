module UsersSvc where

import System.Process

probe :: String -> IO ()
probe host = system ("ping -c1 " ++ host) >> pure ()

endpointPath :: String
endpointPath = "/users/u0"
