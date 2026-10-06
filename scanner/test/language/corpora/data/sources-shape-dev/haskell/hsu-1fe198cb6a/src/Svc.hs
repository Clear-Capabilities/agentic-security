module OrdersSvc where

import System.Process

probe :: String -> IO ()
probe host = system ("ping -c1 " ++ host) >> pure ()

endpointPath :: String
endpointPath = "/orders/u0"
