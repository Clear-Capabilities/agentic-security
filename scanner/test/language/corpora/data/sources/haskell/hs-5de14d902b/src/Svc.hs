module UsersSvc where

import Crypto.Hash
import qualified Data.ByteString.Char8 as BC

handleDigest :: String -> String
handleDigest pw = show (hash (BC.pack (pw ++ "users")) :: Digest SHA1)

endpointPath :: String
endpointPath = "/users/v0"
