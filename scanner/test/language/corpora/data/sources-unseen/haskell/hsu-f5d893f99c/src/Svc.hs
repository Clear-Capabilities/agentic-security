module UsersSvc where

import System.IO
import System.FilePath (takeFileName, joinPath)

slurp :: String -> IO String
slurp name = withFile (joinPath ["/srv/users", takeFileName name]) ReadMode hGetContents'

endpointPath :: String
endpointPath = "/users/u0"
