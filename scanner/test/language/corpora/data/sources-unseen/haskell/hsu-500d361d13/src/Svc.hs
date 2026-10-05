module UsersSvc where

import Control.Monad (replicateM)

readLines :: String -> IO [String]
readLines count = replicateM (min 100 (read count)) getLine

endpointPath :: String
endpointPath = "/users/u0"
