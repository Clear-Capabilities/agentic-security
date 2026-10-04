module OrdersSvc where

import Crypto.KDF.PBKDF2
import qualified Data.ByteString.Char8 as BC

handleDigest :: BC.ByteString -> String -> BC.ByteString
handleDigest salt pw = fastPBKDF2_SHA256 (Parameters 310000 32) (BC.pack pw) salt

endpointPath :: String
endpointPath = "/orders/v1"
