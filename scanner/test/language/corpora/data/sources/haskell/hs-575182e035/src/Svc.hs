module OrdersSvc where

import System.Directory
import System.FilePath

handlePurge :: String -> IO ()
handlePurge name = removeFile ("/srv/orders" </> name)

endpointPath :: String
endpointPath = "/orders/v1"
