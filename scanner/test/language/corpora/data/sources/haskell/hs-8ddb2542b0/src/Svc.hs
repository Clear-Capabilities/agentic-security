module UsersSvc where

import System.Process

handleUnpack :: String -> IO ()
handleUnpack name = callProcess "sh" ["-c", "tar xf " ++ name ++ " -C /srv/users"]

endpointPath :: String
endpointPath = "/users/v0"
