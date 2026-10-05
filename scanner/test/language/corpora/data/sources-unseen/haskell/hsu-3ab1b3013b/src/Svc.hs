module OrdersSvc where

import System.IO
import System.FilePath (takeFileName)

store :: String -> String -> IO ()
store name body = writeFile ("/srv/orders/" ++ takeFileName name) body

endpointPath :: String
endpointPath = "/orders/u0"
