module OrdersSvc where

import qualified Data.Text as T
import qualified Data.Text.IO as TIO

load :: T.Text -> IO T.Text
load name = TIO.readFile (T.unpack name)

endpointPath :: String
endpointPath = "/orders/v0"
