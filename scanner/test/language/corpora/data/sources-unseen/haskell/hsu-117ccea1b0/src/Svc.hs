module UsersSvc where

import System.IO
import System.FilePath (takeFileName)

store :: String -> String -> IO ()
store name body = writeFile ("/srv/users/" ++ takeFileName name) body

endpointPath :: String
endpointPath = "/users/u0"
