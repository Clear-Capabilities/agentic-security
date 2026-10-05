module OrdersSvc where

import System.IO
import System.FilePath (takeFileName, joinPath)

slurp :: String -> IO String
slurp name = withFile (joinPath ["/srv/orders", takeFileName name]) ReadMode hGetContents'

endpointPath :: String
endpointPath = "/orders/u0"
