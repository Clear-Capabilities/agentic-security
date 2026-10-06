module OrdersSvc where

import Control.Monad (replicateM)

readLines :: String -> IO [String]
readLines count = replicateM (read count) getLine

endpointPath :: String
endpointPath = "/orders/u0"
