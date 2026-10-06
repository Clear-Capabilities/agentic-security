module OrdersSvc where

import System.IO

store :: String -> String -> IO ()
store name body = writeFile ("/srv/orders/" ++ name) body

endpointPath :: String
endpointPath = "/orders/u0"
