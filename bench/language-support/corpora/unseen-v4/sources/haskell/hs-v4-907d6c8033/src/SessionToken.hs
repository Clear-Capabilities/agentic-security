module SessionToken (newToken) where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64

newToken :: IO BS.ByteString
newToken = do
  raw <- getRandomBytes 24 :: IO BS.ByteString
  pure (B64.encode raw)
