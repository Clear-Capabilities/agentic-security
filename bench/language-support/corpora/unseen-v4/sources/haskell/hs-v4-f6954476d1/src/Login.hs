module Login (storeUser, checkUser) where

import Data.Digest.Pure.SHA (sha1, showDigest)
import qualified Data.ByteString.Lazy.Char8 as BL
import qualified Data.Map.Strict as M
import Data.IORef

type Users = IORef (M.Map String String)

storeUser :: Users -> String -> String -> IO ()
storeUser ref name password =
  modifyIORef' ref (M.insert name (showDigest (sha1 (BL.pack password))))

checkUser :: Users -> String -> String -> IO Bool
checkUser ref name password = do
  m <- readIORef ref
  pure (M.lookup name m == Just (showDigest (sha1 (BL.pack password))))
