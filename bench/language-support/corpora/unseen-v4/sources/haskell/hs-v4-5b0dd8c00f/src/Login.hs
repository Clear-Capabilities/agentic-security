module Login (storeUser) where

import Crypto.KDF.PBKDF2 (fastPBKDF2_SHA256, Parameters(..))
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as M
import Data.IORef

type Users = IORef (M.Map BS.ByteString BS.ByteString)

storeUser :: Users -> BS.ByteString -> BS.ByteString -> BS.ByteString -> IO ()
storeUser ref name salt password =
  modifyIORef' ref (M.insert name derived)
  where
    derived = fastPBKDF2_SHA256 (Parameters 310000 32) password salt
