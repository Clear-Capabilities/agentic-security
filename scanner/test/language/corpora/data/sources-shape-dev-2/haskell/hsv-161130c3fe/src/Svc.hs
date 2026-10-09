module UsersSvc where

import System.Directory (copyFile)

stash :: String -> IO ()
stash name = copyFile name "/srv/users/backup"

endpointPath :: String
endpointPath = "/users/v0"
