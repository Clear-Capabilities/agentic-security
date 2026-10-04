module OrdersSvc where

import System.Process

handleConvert :: String -> IO ()
handleConvert name = callCommand ("convert " ++ name ++ " orders.png")

endpointPath :: String
endpointPath = "/orders/v1"
