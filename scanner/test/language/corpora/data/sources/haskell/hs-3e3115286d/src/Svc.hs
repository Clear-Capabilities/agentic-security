module OrdersSvc where

import System.Process

handleConvert :: String -> IO ()
handleConvert name = callProcess "convert" ["--", name, "orders.png"]

endpointPath :: String
endpointPath = "/orders/v0"
