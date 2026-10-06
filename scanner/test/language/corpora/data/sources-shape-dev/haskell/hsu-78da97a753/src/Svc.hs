module OrdersSvc where

import System.IO
import System.FilePath (joinPath)

slurp :: String -> IO String
slurp name = withFile (joinPath ["/srv/orders", name]) ReadMode hGetContents'

endpointPath :: String
endpointPath = "/orders/u0"
