module UsersSvc where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString.Char8 as BC

checksum :: BC.ByteString -> BC.ByteString
checksum payload = SHA256.hash payload

endpointPath :: String
endpointPath = "/users/v0"
