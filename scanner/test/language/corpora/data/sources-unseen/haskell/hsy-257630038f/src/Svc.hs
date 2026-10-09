module OrdersSvc where

import System.Process.Typed

unpack :: String -> IO ()
unpack archive = runProcess_ (proc "tar" ["xzf", archive, "-C", "/srv/orders"])

endpointPath :: String
endpointPath = "/orders/v0"
