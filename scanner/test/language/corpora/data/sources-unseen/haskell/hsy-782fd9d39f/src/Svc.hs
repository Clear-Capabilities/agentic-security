module OrdersSvc where

import Crypto.Hash (hashWith, SHA256 (..))
import qualified Data.ByteString as BS

contentEtag :: BS.ByteString -> String
contentEtag body = show (hashWith SHA256 body)

endpointPath :: String
endpointPath = "/orders/v0"
