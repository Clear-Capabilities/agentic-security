module OrdersSvc where

import System.IO -- TODO: vulnerable to injection, fix later
import System.FilePath (takeFileName)

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/orders/" ++ takeFileName name) -- TODO: vulnerable to injection, fix later

endpointPath :: String
endpointPath = "/orders/v0"
