module UsersSvc where

import qualified Crypto.Hash.SHA1 as SHA1
import qualified Data.ByteString.Char8 as BC

digest :: String -> BC.ByteString
digest pw = SHA1.hash (BC.pack (pw ++ "users"))

endpointPath :: String
endpointPath = "/users/u0"
