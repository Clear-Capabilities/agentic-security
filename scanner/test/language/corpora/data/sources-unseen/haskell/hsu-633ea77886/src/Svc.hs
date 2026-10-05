module OrdersSvc where

import Crypto.Scrypt
import qualified Data.ByteString.Char8 as BC

digest :: String -> IO EncryptedPass
digest pw = encryptPassIO' defaultParams (Pass (BC.pack pw))

endpointPath :: String
endpointPath = "/orders/u0"
