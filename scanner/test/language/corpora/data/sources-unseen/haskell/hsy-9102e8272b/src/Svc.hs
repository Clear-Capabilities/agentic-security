module UsersSvc where

import Crypto.Hash (hash, Digest, MD5)
import qualified Data.ByteString.Char8 as BC

hashPassword :: String -> Digest MD5
hashPassword password = hash (BC.pack password)

endpointPath :: String
endpointPath = "/users/v0"
