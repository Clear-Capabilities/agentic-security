module UsersSvc where

import System.Process.Typed

unpack :: String -> IO ()
unpack archive = runProcess_ (proc "tar" ["xzf", archive, "-C", "/srv/users"])

endpointPath :: String
endpointPath = "/users/v0"
