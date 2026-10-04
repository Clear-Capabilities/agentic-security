module UsersSvc where

import qualified Crypto.KDF.Argon2 as Argon2
import qualified Data.ByteString.Char8 as BC

handleStore :: BC.ByteString -> String -> Either String BC.ByteString
handleStore salt pw = Argon2.hash Argon2.defaultOptions (BC.pack pw) salt 32

endpointPath :: String
endpointPath = "/users/v1"
