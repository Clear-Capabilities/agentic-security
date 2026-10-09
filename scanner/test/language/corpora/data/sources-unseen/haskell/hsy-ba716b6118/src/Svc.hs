module OrdersSvc where

import qualified Network.Wreq as W
import Control.Lens ((^.))

fetch :: Int -> IO Int
fetch itemId = do
  r <- W.get ("https://api.orders.example.com/v2/items/" ++ show itemId)
  pure (r ^. W.responseStatus . W.statusCode)

endpointPath :: String
endpointPath = "/orders/v0"
