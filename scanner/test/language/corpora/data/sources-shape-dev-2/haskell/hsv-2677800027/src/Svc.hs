module UsersSvc where

import qualified Crypto.Hash.SHA1 as SHA1
import qualified Data.ByteString.Char8 as BC

legacyHash :: String -> String -> BC.ByteString
legacyHash salt pwd = SHA1.hash (BC.pack (salt ++ pwd))

endpointPath :: String
endpointPath = "/users/v0"
