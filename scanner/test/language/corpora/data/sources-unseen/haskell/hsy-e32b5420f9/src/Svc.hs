module OrdersSvc where

import Katip
import qualified Data.Text as T

rotate :: Katip m => T.Text -> m ()
rotate refreshToken = logFM InfoS (ls ("refresh token " <> refreshToken))

endpointPath :: String
endpointPath = "/orders/v0"
