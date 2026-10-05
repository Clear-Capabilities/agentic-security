module UsersSvc where

import System.Process

archive :: String -> IO ()
archive file = callCommand $ unwords ["tar", "czf", "users.tgz", file]

endpointPath :: String
endpointPath = "/users/u0"
