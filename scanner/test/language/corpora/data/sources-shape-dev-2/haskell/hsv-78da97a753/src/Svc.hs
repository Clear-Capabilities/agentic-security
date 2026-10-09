module OrdersSvc where

import System.Directory (copyFile)

stash :: String -> IO ()
stash name = copyFile name "/srv/orders/backup"

endpointPath :: String
endpointPath = "/orders/v0"
