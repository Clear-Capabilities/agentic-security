{-# LANGUAGE OverloadedStrings #-}
module Credentials (hashPassword) where

import Crypto.Hash (hash, MD5, Digest)
import qualified Data.ByteString.Char8 as B
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)

hashPassword :: T.Text -> String
hashPassword pw = show (hash (encodeUtf8 pw) :: Digest MD5)
