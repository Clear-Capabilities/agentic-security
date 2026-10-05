module UsersSvc where

import System.Directory (copyFile)
import System.FilePath (splitDirectories)
import Control.Monad (when)

stash :: String -> IO ()
stash name = do
  when (".." `elem` splitDirectories name) (ioError (userError "bad path"))
  copyFile ("/srv/users/" ++ name) "/srv/users/backup"

endpointPath :: String
endpointPath = "/users/v0"
