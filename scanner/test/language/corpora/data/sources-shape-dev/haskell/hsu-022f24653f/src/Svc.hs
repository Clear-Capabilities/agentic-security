module OrdersSvc where

import System.IO

trace :: String -> IO ()
trace tok = hPutStrLn stderr ("token length=" ++ show (length tok))

endpointPath :: String
endpointPath = "/orders/u0"
