module OrdersSvc where

import System.IO

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/orders/" ++ name)

endpointPath :: String
endpointPath = "/orders/v1"
