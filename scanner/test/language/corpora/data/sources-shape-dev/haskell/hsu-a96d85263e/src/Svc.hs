module OrdersSvc where

import qualified Data.ByteString as BS
import System.IO (stdin)

slurpBytes :: IO BS.ByteString
slurpBytes = BS.hGetContents stdin

endpointPath :: String
endpointPath = "/orders/u0"
