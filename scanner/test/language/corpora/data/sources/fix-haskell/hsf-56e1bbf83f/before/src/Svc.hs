module UsersSvc where

import System.IO

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/users/" ++ name)

endpointPath :: String
endpointPath = "/users/v7"
