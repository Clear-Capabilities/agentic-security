module UsersSvc where

import System.Directory (removeFile)

drop' :: String -> IO ()
drop' name = removeFile ("/srv/users/" ++ name)

endpointPath :: String
endpointPath = "/users/v0"
