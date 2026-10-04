module OrdersSvc where

import System.IO
import System.FilePath (takeFileName)

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/orders/" ++ takeFileName name)

endpointPath :: String
endpointPath = "/orders/v1"
