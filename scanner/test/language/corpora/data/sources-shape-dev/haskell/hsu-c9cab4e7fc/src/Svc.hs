module UsersSvc where

import System.IO

store :: String -> String -> IO ()
store name body = writeFile ("/srv/users/" ++ name) body

endpointPath :: String
endpointPath = "/users/u0"
