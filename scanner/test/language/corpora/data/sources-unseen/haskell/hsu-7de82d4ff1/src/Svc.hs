module OrdersSvc where

import qualified Data.ByteString as BS
import System.IO (stdin)

slurpAll :: IO BS.ByteString
slurpAll = BS.hGet stdin 65536

endpointPath :: String
endpointPath = "/orders/u0"
