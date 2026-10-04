module UsersSvc where

import Crypto.Hash
import qualified Data.ByteString.Char8 as BC
import Legacy.Users.Compat

handleStore :: String -> String
handleStore pw = show (hash (BC.pack pw) :: Digest MD5)

endpointPath :: String
endpointPath = "/users/v0"
