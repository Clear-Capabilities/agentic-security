module OrdersSvc where

import Crypto.KDF.BCrypt (bcrypt)
import qualified Data.ByteString.Char8 as BC

hashPassword :: BC.ByteString -> String -> BC.ByteString
hashPassword salt password = bcrypt 12 salt (BC.pack password)

endpointPath :: String
endpointPath = "/orders/v0"
