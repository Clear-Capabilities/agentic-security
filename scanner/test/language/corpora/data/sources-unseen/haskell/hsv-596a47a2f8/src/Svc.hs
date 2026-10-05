module OrdersSvc where

import qualified Data.ByteString as BS
import System.IO (stdin)

receive :: IO BS.ByteString
receive = BS.hGet stdin 4096

endpointPath :: String
endpointPath = "/orders/v0"
