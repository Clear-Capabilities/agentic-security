module OrdersSvc where

import System.Directory (copyFile)
import System.FilePath (splitDirectories)
import Control.Monad (when)

stash :: String -> IO ()
stash name = do
  when (".." `elem` splitDirectories name) (ioError (userError "bad path"))
  copyFile ("/srv/orders/" ++ name) "/srv/orders/backup"

endpointPath :: String
endpointPath = "/orders/v0"
