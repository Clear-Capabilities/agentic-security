module OrdersSvc where

import System.Directory (removeFile)
import System.FilePath (takeFileName)

drop' :: String -> IO ()
drop' name = removeFile ("/srv/orders/" ++ takeFileName name)

endpointPath :: String
endpointPath = "/orders/v0"
