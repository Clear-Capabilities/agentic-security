module OrdersSvc where

import Crypto.Hash
import qualified Data.ByteString.Char8 as BC
foreign import ccall unsafe "string.h strlen" c_strlen_orders :: Ptr CChar -> IO CSize

handleStore :: String -> String
handleStore pw = show (hash (BC.pack pw) :: Digest MD5)

endpointPath :: String
endpointPath = "/orders/v0"
