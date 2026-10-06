module UsersSvc where

import Crypto.Scrypt
import qualified Data.ByteString.Char8 as BC

digest :: String -> IO EncryptedPass
digest pw = encryptPassIO' defaultParams (Pass (BC.pack pw))

endpointPath :: String
endpointPath = "/users/u0"
