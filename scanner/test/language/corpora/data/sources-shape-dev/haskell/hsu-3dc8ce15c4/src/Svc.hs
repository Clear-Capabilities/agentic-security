module OrdersSvc where

import qualified Network.Wreq as W

pull :: String -> IO ()
pull url = W.get url >>= \r -> print (r W.^. W.responseStatus)

endpointPath :: String
endpointPath = "/orders/u0"
