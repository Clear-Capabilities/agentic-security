module OrdersSvc where

import qualified Data.ByteString.Lazy as BL
import System.IO (stdin)

slurp :: IO BL.ByteString
slurp = BL.hGetContents stdin

endpointPath :: String
endpointPath = "/orders/v0"
