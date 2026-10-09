module UsersSvc where

import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString.Lazy.Char8 as BL

storePassword :: String -> BL.ByteString
storePassword password = BL.fromStrict (MD5.hashlazy (BL.pack password))

endpointPath :: String
endpointPath = "/users/v0"
