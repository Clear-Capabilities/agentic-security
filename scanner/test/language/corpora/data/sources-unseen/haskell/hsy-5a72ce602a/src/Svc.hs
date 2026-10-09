module UsersSvc where

import Crypto.KDF.Scrypt (generate, Parameters (..))
import qualified Data.ByteString.Char8 as BC

storeCredential :: BC.ByteString -> String -> BC.ByteString
storeCredential salt password = generate (Parameters { n = 16384, r = 8, p = 1, outputLength = 64 }) (BC.pack password) salt

endpointPath :: String
endpointPath = "/users/v0"
