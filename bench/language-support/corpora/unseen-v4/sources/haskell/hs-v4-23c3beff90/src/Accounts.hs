{-# LANGUAGE OverloadedStrings #-}
module Accounts (newAccount) where

import Crypto.Argon2 (hashEncoded, defaultHashOptions)
import qualified Data.ByteString as BS
import qualified Data.Text as T
import Database.SQLite.Simple

newAccount :: Connection -> BS.ByteString -> BS.ByteString -> BS.ByteString -> IO ()
newAccount conn user salt pass =
  case hashEncoded defaultHashOptions pass salt of
    Left _    -> fail "hashing failed"
    Right enc -> execute conn "INSERT INTO accounts (user, pw) VALUES (?, ?)" (user, T.unpack enc)
