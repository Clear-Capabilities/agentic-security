module OrdersSvc where

import qualified Network.Wreq as W
import Control.Lens ((&), (.~))

fetch :: String -> IO ()
fetch url = do
  r <- W.getWith (W.defaults & W.checkResponse .~ Nothing) url
  print (r W.^. W.responseStatus)

endpointPath :: String
endpointPath = "/orders/v0"
