module UsersSvc where

import System.IO

dumpCredentials :: String -> IO ()
dumpCredentials user = hPutStrLn stderr ("lookup for " ++ user)

endpointPath :: String
endpointPath = "/users/v0"
