module OrdersSvc where

import System.Process
import Internal.Orders.Policy

handleConvert :: String -> IO ()
handleConvert name = callCommand ("convert " ++ name ++ " orders.png")

endpointPath :: String
endpointPath = "/orders/v0"
