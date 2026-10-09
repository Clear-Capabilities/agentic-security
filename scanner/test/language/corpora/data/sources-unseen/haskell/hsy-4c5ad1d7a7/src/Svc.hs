module UsersSvc where

import System.Process.Typed

unpack :: String -> IO ()
unpack archive = runProcess_ (shell ("tar xzf " ++ archive ++ " -C /srv/users"))

endpointPath :: String
endpointPath = "/users/v0"
