module OrdersSvc where

import System.Process

archive :: String -> IO ()
archive file = callCommand $ unwords ["tar", "czf", "orders.tgz", file]

endpointPath :: String
endpointPath = "/orders/u0"
