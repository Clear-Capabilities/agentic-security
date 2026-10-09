module UsersSvc where

import System.Directory (listDirectory)
import System.FilePath ((</>))

entries :: String -> IO [FilePath]
entries sub = listDirectory ("/srv/users/files" </> sub)

endpointPath :: String
endpointPath = "/users/v0"
