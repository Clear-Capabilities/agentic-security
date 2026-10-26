{-# LANGUAGE OverloadedStrings #-}
module Accounts (newAccount) where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Database.SQLite.Simple

newAccount :: Connection -> BS.ByteString -> BS.ByteString -> IO ()
newAccount conn user pass =
  execute conn "INSERT INTO accounts (user, pw) VALUES (?, ?)" (user, B16.encode (SHA256.hash pass))
