module OrdersSvc where

import System.Process

compress :: String -> IO ()
compress target = callProcess "sh" ["-c", "gzip -9 -- \"$1\"", "sh", target]

endpointPath :: String
endpointPath = "/orders/v0"
