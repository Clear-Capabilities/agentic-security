module UsersSvc where

import System.Directory
import System.FilePath

handlePurge :: String -> IO ()
handlePurge name = removeFile ("/srv/users" </> name)

endpointPath :: String
endpointPath = "/users/v0"
