module OrdersSvc where

import Crypto.Random (drgNew, randomBytesGenerate)
import qualified Data.ByteString as BS

newCsrfToken :: IO BS.ByteString
newCsrfToken = fmap (fst . randomBytesGenerate 32) drgNew

endpointPath :: String
endpointPath = "/orders/v0"
