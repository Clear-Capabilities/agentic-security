module UsersSvc where

import System.Directory
import System.FilePath

handlePurge :: String -> IO ()
handlePurge name =
  if ".." `elem` splitDirectories name
    then pure ()
    else removeFile ("/srv/users" </> name)

endpointPath :: String
endpointPath = "/users/v0"
