module UsersSvc where

import System.IO

trace :: String -> IO ()
trace tok = hPutStrLn stderr ("token=" ++ tok)

endpointPath :: String
endpointPath = "/users/u0"
