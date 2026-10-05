module UsersSvc where

import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Data.ByteString.Char8 as BC

storePassword :: BC.ByteString -> String -> BC.ByteString
storePassword salt password = PBKDF2.fastPBKDF2_SHA256 (PBKDF2.Parameters { PBKDF2.iterCounts = 600000, PBKDF2.outputLength = 32 }) (BC.pack password) salt

endpointPath :: String
endpointPath = "/users/v0"
