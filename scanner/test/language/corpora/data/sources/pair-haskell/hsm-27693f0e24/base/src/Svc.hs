module UsersSvc where

import System.IO
import System.FilePath (takeFileName)

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/users/" ++ takeFileName name)

endpointPath :: String
endpointPath = "/users/v9"
