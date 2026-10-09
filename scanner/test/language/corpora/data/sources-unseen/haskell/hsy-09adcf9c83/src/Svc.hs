module OrdersSvc where

import Text.Printf (printf)

debugSession :: String -> String -> IO ()
debugSession sid apiSecret = printf "session %s secret %s\n" sid apiSecret

endpointPath :: String
endpointPath = "/orders/v0"
