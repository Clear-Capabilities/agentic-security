module OrdersSvc where

import System.IO

trace :: String -> IO ()
trace tok = hPutStrLn stderr ("token=" ++ tok)

endpointPath :: String
endpointPath = "/orders/u0"
