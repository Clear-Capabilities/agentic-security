module OrdersSvc where

import System.Process

handleUnpack :: String -> IO ()
handleUnpack name = callProcess "sh" ["-c", "tar xf " ++ name ++ " -C /srv/orders"]

endpointPath :: String
endpointPath = "/orders/v0"
