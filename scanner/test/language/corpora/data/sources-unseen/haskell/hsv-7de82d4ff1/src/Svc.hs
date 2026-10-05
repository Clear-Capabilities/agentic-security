module OrdersSvc where

import qualified Data.ByteString.Lazy as BL
import System.IO (stdin)

slurp :: IO BL.ByteString
slurp = fmap (BL.take 65536) (BL.hGetContents stdin)

endpointPath :: String
endpointPath = "/orders/v0"
