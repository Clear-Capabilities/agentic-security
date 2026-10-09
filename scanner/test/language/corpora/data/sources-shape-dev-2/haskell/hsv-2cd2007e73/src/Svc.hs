module UsersSvc where

import System.Directory (removeFile)
import System.FilePath (takeFileName)

drop' :: String -> IO ()
drop' name = removeFile ("/srv/users/" ++ takeFileName name)

endpointPath :: String
endpointPath = "/users/v0"
