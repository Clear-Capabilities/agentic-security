module UsersSvc where

import Katip
import qualified Data.Text as T

rotate :: Katip m => T.Text -> m ()
rotate user = logFM InfoS (ls ("refresh token rotated for " <> user))

endpointPath :: String
endpointPath = "/users/v0"
