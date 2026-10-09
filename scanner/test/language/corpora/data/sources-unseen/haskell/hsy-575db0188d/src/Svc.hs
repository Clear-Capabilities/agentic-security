module OrdersSvc where

import System.Directory (listDirectory)
import System.FilePath ((</>))

entries :: String -> IO [FilePath]
entries sub = listDirectory ("/srv/orders/files" </> sub)

endpointPath :: String
endpointPath = "/orders/v0"
