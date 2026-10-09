module OrdersSvc where

import System.IO

saveUpload :: String -> String -> IO ()
saveUpload name content = withFile name WriteMode (\h -> hPutStr h content)

endpointPath :: String
endpointPath = "/orders/v0"
