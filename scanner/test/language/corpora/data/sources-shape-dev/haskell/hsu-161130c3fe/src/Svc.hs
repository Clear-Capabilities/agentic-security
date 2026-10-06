module UsersSvc where

import System.IO
import System.FilePath (joinPath)

slurp :: String -> IO String
slurp name = withFile (joinPath ["/srv/users", name]) ReadMode hGetContents'

endpointPath :: String
endpointPath = "/users/u0"
