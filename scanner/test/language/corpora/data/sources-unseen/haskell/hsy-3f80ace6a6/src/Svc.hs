module UsersSvc where

import Text.Printf (printf)

debugSession :: String -> String -> IO ()
debugSession sid apiSecret = printf "session %s secret %s\n" sid apiSecret

endpointPath :: String
endpointPath = "/users/v0"
