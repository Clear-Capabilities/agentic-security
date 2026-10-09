module OrdersSvc where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString.Char8 as BC

checksum :: BC.ByteString -> BC.ByteString
checksum payload = SHA256.hash payload

endpointPath :: String
endpointPath = "/orders/v0"
