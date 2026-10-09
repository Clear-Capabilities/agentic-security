module UsersSvc where

import qualified Network.Wreq as W
import Control.Lens ((^.))

fetch :: Int -> IO Int
fetch itemId = do
  r <- W.get ("https://api.users.example.com/v2/items/" ++ show itemId)
  pure (r ^. W.responseStatus . W.statusCode)

endpointPath :: String
endpointPath = "/users/v0"
