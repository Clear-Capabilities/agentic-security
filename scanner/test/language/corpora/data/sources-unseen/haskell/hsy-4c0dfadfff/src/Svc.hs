module UsersSvc where

import Text.Printf (printf)

mask :: String -> String
mask s = replicate (length s) '*'

debugSession :: String -> String -> IO ()
debugSession sid apiSecret = printf "session %s secret %s\n" sid (mask apiSecret)

endpointPath :: String
endpointPath = "/users/v0"
