module OrdersSvc where

import qualified Data.Text.IO as TIO
import qualified Data.Text as T

slurpText :: IO T.Text
slurpText = TIO.getContents

endpointPath :: String
endpointPath = "/orders/v0"
