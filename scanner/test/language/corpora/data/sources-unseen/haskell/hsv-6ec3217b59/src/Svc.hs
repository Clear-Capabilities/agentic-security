module OrdersSvc where

import System.Directory (removeFile)

drop' :: String -> IO ()
drop' name = removeFile ("/srv/orders/" ++ name)

endpointPath :: String
endpointPath = "/orders/v0"
